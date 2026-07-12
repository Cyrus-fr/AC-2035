"""Injects honeytokens into GKE workloads (env vars) and GCP Secret Manager.

Never logs token_value — only token_id and the target locations. Both
targets degrade gracefully to a logged warning + skip when the environment
isn't configured (no kubeconfig, no GCP_PROJECT_ID), so local dev works
without a live cluster or GCP credentials.
"""

from __future__ import annotations

import os
from typing import Optional

from google.api_core.exceptions import GoogleAPICallError
from google.auth.exceptions import DefaultCredentialsError
from google.cloud import secretmanager
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from kubernetes.config import ConfigException
from loguru import logger

from .generator import Token

_config_loaded = False
_config_available = False


def _ensure_k8s_config() -> bool:
    """Load kube config once per process (in-cluster first, kubeconfig
    fallback). Returns whether a usable config was found."""
    global _config_loaded, _config_available
    if _config_loaded:
        return _config_available
    _config_loaded = True

    try:
        config.load_incluster_config()
        logger.info("Loaded in-cluster Kubernetes config")
        _config_available = True
    except ConfigException:
        try:
            config.load_kube_config()
            logger.info("Loaded local kubeconfig")
            _config_available = True
        except ConfigException:
            logger.warning(
                "No Kubernetes config found (in-cluster or kubeconfig) — skipping GKE injection"
            )
            _config_available = False

    return _config_available


def _resolve_owning_deployment(
    core_api: client.CoreV1Api, apps_api: client.AppsV1Api, pod: str, namespace: str
) -> Optional[str]:
    """Walk Pod -> ReplicaSet -> Deployment ownerReferences.

    A live Pod's spec is immutable after creation (aside from `.image`), and
    even a permitted patch is wiped out the moment the pod is rescheduled.
    The durable injection point is the parent Deployment's pod template,
    which triggers a clean rolling update. Returns None for a standalone pod
    with no owning Deployment (e.g. a bare test pod).
    """
    try:
        pod_obj = core_api.read_namespaced_pod(name=pod, namespace=namespace)
    except ApiException as e:
        logger.warning("Could not read pod {}/{}: {} {}", namespace, pod, e.status, e.reason)
        return None

    rs_owner = next(
        (o for o in (pod_obj.metadata.owner_references or []) if o.kind == "ReplicaSet"), None
    )
    if rs_owner is None:
        return None

    try:
        rs_obj = apps_api.read_namespaced_replica_set(name=rs_owner.name, namespace=namespace)
    except ApiException:
        return None

    deploy_owner = next(
        (o for o in (rs_obj.metadata.owner_references or []) if o.kind == "Deployment"), None
    )
    return deploy_owner.name if deploy_owner else None


def _patch_deployment_env(
    apps_api: client.AppsV1Api, deployment: str, namespace: str, env_name: str, token: Token
) -> bool:
    try:
        deploy = apps_api.read_namespaced_deployment(name=deployment, namespace=namespace)
        container_name = deploy.spec.template.spec.containers[0].name

        # Strategic merge patch on the pod template: containers/env merge by
        # "name" key, so this only adds/overwrites env_name. Patching the
        # template (not the live pod) triggers a rolling update — the new
        # env var lands in a fresh pod and survives rescheduling since it's
        # now part of the controller's spec, not just the running instance.
        patch = {
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {
                                "name": container_name,
                                "env": [{"name": env_name, "value": token.token_value}],
                            }
                        ]
                    }
                }
            }
        }
        apps_api.patch_namespaced_deployment(name=deployment, namespace=namespace, body=patch)
        logger.info(
            "Injected token {} into Deployment {}/{} as env var {} (rolling update triggered)",
            token.token_id, namespace, deployment, env_name,
        )
        return True
    except ApiException as e:
        logger.warning(
            "Failed to inject token {} into Deployment {}/{}: {} {}",
            token.token_id, namespace, deployment, e.status, e.reason,
        )
        return False


def inject_pod_env(pod: str, namespace: str, token: Token) -> bool:
    """Inject `token`'s value as an env var reachable by `pod`.

    Resolves `pod` up to its owning Deployment and patches the Deployment's
    pod template rather than the live Pod object directly — a durable
    rolling-update injection instead of one a reschedule silently erases
    (or a real API server rejects outright, since Pod specs are immutable
    post-creation aside from `.image`). The env var name is keyed by
    token_type, not token_id, so rotation overwrites the same key with a
    new value instead of accumulating a new var per rotation.
    """
    if not _ensure_k8s_config():
        return False

    core_api = client.CoreV1Api()
    apps_api = client.AppsV1Api()
    env_name = f"HONEYTOKEN_{token.token_type.upper()}"

    deployment = _resolve_owning_deployment(core_api, apps_api, pod, namespace)
    if deployment is None:
        logger.warning(
            "Pod {}/{} has no owning Deployment — skipping injection. Honeytoken "
            "pods must be managed by a Deployment so the env var survives "
            "rescheduling.",
            namespace, pod,
        )
        return False

    return _patch_deployment_env(apps_api, deployment, namespace, env_name, token)


def inject_secret_manager(token: Token, project_id: str) -> Optional[str]:
    """Create a Secret Manager secret for `token` and add its first version."""
    if not project_id:
        logger.warning(
            "GCP_PROJECT_ID is empty — skipping Secret Manager injection for token {}",
            token.token_id,
        )
        return None

    secret_id = f"ac2035-{token.token_id}"
    parent = f"projects/{project_id}"

    try:
        sm_client = secretmanager.SecretManagerServiceClient()
        secret = sm_client.create_secret(
            request={
                "parent": parent,
                "secret_id": secret_id,
                "secret": {"replication": {"automatic": {}}},
            }
        )
        sm_client.add_secret_version(
            request={"parent": secret.name, "payload": {"data": token.token_value.encode("utf-8")}}
        )
        path = f"{parent}/secrets/{secret_id}"
        logger.info("Injected token {} into Secret Manager at {}", token.token_id, path)
        return path
    except DefaultCredentialsError as e:
        logger.warning(
            "No GCP credentials available — skipping Secret Manager injection for token {}: {}",
            token.token_id, e,
        )
        return None
    except GoogleAPICallError as e:
        logger.warning("Secret Manager injection failed for token {}: {}", token.token_id, e)
        return None


def rotate_secret_manager(token: Token, secret_manager_path: str) -> bool:
    """Add a new version to an existing Secret Manager secret during rotation."""
    if not secret_manager_path:
        return False

    try:
        sm_client = secretmanager.SecretManagerServiceClient()
        sm_client.add_secret_version(
            request={
                "parent": secret_manager_path,
                "payload": {"data": token.token_value.encode("utf-8")},
            }
        )
        logger.info(
            "Rotated Secret Manager secret {} with new version for token {}",
            secret_manager_path, token.token_id,
        )
        return True
    except (DefaultCredentialsError, GoogleAPICallError) as e:
        logger.warning("Failed to rotate Secret Manager secret {}: {}", secret_manager_path, e)
        return False


# token_type string → the __u8 enum the eBPF map expects.
_TOKEN_TYPE_TO_INT = {"gcp_key": 0, "gcp_api_key": 1, "db_connection": 2, "api_token": 3}


def register_inodes_with_detector(token_list, bpf_handle=None) -> int:
    """Close the deploy → detect loop: for every token injected as a *file*,
    stat it for its inode and add it to the eBPF watched_inodes map so the
    kernel detector attributes any access to it.

    Env-var / Secret-Manager tokens have no on-disk file and are skipped.
    Each token may be a Token dataclass or a dict; a file path is taken from
    a `file_path` attribute/key. No-ops cleanly with no eBPF handle (off
    Linux / detector not loaded) after computing the inode map.
    """
    inode_map: dict[int, dict] = {}
    for token in token_list:
        if isinstance(token, dict):
            file_path = token.get("file_path")
            token_id = token.get("token_id")
            token_type = token.get("token_type")
            pod = token.get("target_pod") or token.get("pod_id") or ""
            namespace = token.get("target_namespace") or token.get("namespace") or ""
        else:
            file_path = getattr(token, "file_path", None)
            token_id = getattr(token, "token_id", None)
            token_type = getattr(token, "token_type", None)
            pod = getattr(token, "target_pod", None) or ""
            namespace = getattr(token, "target_namespace", None) or ""

        if not file_path:
            logger.debug("Token {} has no file_path — not an inode-watchable honeytoken, skipping", token_id)
            continue
        try:
            inode = os.stat(file_path).st_ino
        except OSError as e:
            logger.warning("Could not stat honeytoken file {} for token {}: {}", file_path, token_id, e)
            continue

        inode_map[inode] = {
            "token_id": token_id,
            "token_type": _TOKEN_TYPE_TO_INT.get(token_type, 3),
            "pod_id": pod,
            "namespace": namespace,
        }

    if not inode_map:
        logger.info("No file-based honeytokens to register with the eBPF detector")
        return 0

    if bpf_handle is None:
        logger.info(
            "Computed {} inode(s) to watch, but no eBPF detector handle is loaded "
            "(off-Linux or detector not running) — skipping map update",
            len(inode_map),
        )
        return 0

    from detector.ebpf import loader

    return loader.update_inodes(bpf_handle, inode_map)
