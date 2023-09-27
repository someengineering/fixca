import sys
import base64
from typing import Optional
from resotolib.logger import log
from kubernetes import client, config
from kubernetes.client.exceptions import ApiException


def k8s_client() -> client.CoreV1Api:
    try:
        config.load_incluster_config()
    except config.config_exception.ConfigException:
        try:
            config.load_kube_config()
        except config.config_exception.ConfigException as e:
            log.error(f"Failed to load Kubernetes config: {e}")
            sys.exit(1)
    return client.CoreV1Api()


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
    secret = client.V1Secret(
        metadata=client.V1ObjectMeta(name=secret_name), type="Opaque", data=secret_data
    )
    try:
        k8s.read_namespaced_secret(name=secret_name, namespace=namespace)
        k8s.replace_namespaced_secret(name=secret_name, namespace=namespace, body=secret)
    except ApiException as e:
        if e.status == 404:
            k8s.create_namespaced_secret(namespace=namespace, body=secret)
        else:
            raise