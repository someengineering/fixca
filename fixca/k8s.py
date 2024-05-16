import sys
import base64
from typing import Optional
from fixlib.logger import log
from kubernetes import client, config
from kubernetes.client.exceptions import ApiException
from kubernetes.client.models.v1_namespace_list import V1NamespaceList
from kubernetes.client.models.v1_namespace import V1Namespace
from .utils import memoize


def k8s_client() -> client.CoreV1Api:
    k8s_config_load()
    return client.CoreV1Api()


@memoize()
def k8s_config_load() -> None:
    try:
        config.load_incluster_config()
    except config.config_exception.ConfigException:
        try:
            config.load_kube_config()
        except config.config_exception.ConfigException as e:
            log.critical(f"Failed to load Kubernetes config: {e}")
            sys.exit(1)


def get_secret(namespace: str, secret_name: str) -> Optional[dict[str, str]]:
    k8s = k8s_client()

    try:
        secret = k8s.read_namespaced_secret(secret_name, namespace)
    except ApiException as e:
        if e.status == 404:
            return None
        else:
            raise

    assert isinstance(secret, client.V1Secret)
    assert isinstance(secret.data, dict)
    return {k: base64.b64decode(v).decode("utf-8") for k, v in secret.data.items()}


def set_secret(namespace: str, secret_name: str, data: dict[str, str]) -> None:
    k8s = k8s_client()

    secret_data = {k: base64.b64encode(v.encode("utf-8")).decode("utf-8") for k, v in data.items()}
    secret = client.V1Secret(metadata=client.V1ObjectMeta(name=secret_name), type="Opaque", data=secret_data)
    try:
        k8s.read_namespaced_secret(name=secret_name, namespace=namespace)
        k8s.replace_namespaced_secret(name=secret_name, namespace=namespace, body=secret)
    except ApiException as e:
        if e.status == 404:
            try:
                k8s.create_namespaced_secret(namespace=namespace, body=secret)
            except ApiException as e:
                if e.status == 404:
                    log.critical(f"Namespace {namespace} does not exist")
                    sys.exit(1)
                else:
                    raise
        else:
            raise


def get_namespaces(exclude_system: bool = True) -> list[str]:
    k8s = k8s_client()

    system_namespaces = ["kube-system", "kube-public", "kube-node-lease"]

    try:
        namespaces: V1NamespaceList = k8s.list_namespace()
        return [
            ns.metadata.name
            for ns in namespaces.items
            if isinstance(ns, V1Namespace) and (not exclude_system or ns.metadata.name not in system_namespaces)
        ]
    except ApiException as e:
        log.error(f"Failed to fetch namespaces: {e}")
        return []
