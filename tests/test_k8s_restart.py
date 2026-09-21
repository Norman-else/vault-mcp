import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from vault_mcp.web_ui import K8S_NAME_RE, VaultWebUI, pod_state, rollout_state


def _deploy(generation=2, observed=2, spec=3, updated=3, current=3, ready=3,
            available=3, conditions=None):
    return {
        'metadata': {'generation': generation},
        'spec': {'replicas': spec},
        'status': {
            'observedGeneration': observed,
            'replicas': current,
            'updatedReplicas': updated,
            'readyReplicas': ready,
            'availableReplicas': available,
            'conditions': conditions or [],
        },
    }


class TestRolloutState(unittest.TestCase):
    def test_complete(self):
        state = rollout_state(_deploy())
        self.assertTrue(state['complete'])
        self.assertFalse(state['failed'])
        self.assertEqual(state['total'], 3)

    def test_in_progress_old_generation(self):
        state = rollout_state(_deploy(generation=3, observed=2))
        self.assertFalse(state['complete'])

    def test_in_progress_surplus_old_replicas(self):
        # 4 pods running but only 3 updated: old ReplicaSet still draining
        state = rollout_state(_deploy(current=4, updated=3))
        self.assertFalse(state['complete'])

    def test_in_progress_not_all_available(self):
        state = rollout_state(_deploy(available=1, ready=1))
        self.assertFalse(state['complete'])

    def test_failed_progress_deadline(self):
        state = rollout_state(_deploy(
            generation=3, observed=3, updated=1, ready=1, available=1,
            conditions=[{'type': 'Progressing',
                         'reason': 'ProgressDeadlineExceeded',
                         'message': 'deadline exceeded'}]))
        self.assertTrue(state['failed'])
        self.assertFalse(state['complete'])
        self.assertEqual(state['message'], 'deadline exceeded')

    def test_empty_status(self):
        state = rollout_state({'metadata': {'generation': 1}, 'spec': {'replicas': 2}})
        self.assertFalse(state['complete'])
        self.assertEqual(state['updated'], 0)


class TestPodState(unittest.TestCase):
    def test_running_ready(self):
        state = pod_state({
            'metadata': {'name': 'app-1'},
            'status': {'phase': 'Running',
                       'containerStatuses': [{'ready': True, 'state': {'running': {}}}]},
        })
        self.assertEqual(state, {'name': 'app-1', 'phase': 'Running', 'ready': '1/1',
                                 'created': None})

    def test_terminating(self):
        state = pod_state({
            'metadata': {'name': 'app-2', 'deletionTimestamp': '2026-08-11T00:00:00Z'},
            'status': {'phase': 'Running',
                       'containerStatuses': [{'ready': True, 'state': {'running': {}}}]},
        })
        self.assertEqual(state['phase'], 'Terminating')

    def test_waiting_reason(self):
        state = pod_state({
            'metadata': {'name': 'app-3'},
            'status': {'phase': 'Pending',
                       'containerStatuses': [
                           {'ready': False,
                            'state': {'waiting': {'reason': 'ContainerCreating'}}}]},
        })
        self.assertEqual(state['phase'], 'ContainerCreating')
        self.assertEqual(state['ready'], '0/1')

    def test_pending_without_container_statuses(self):
        state = pod_state({
            'metadata': {'name': 'app-4'},
            'spec': {'containers': [{}, {}]},
            'status': {'phase': 'Pending'},
        })
        self.assertEqual(state, {'name': 'app-4', 'phase': 'Pending', 'ready': '0/2',
                                 'created': None})


class TestRestartPodDetails(unittest.TestCase):
    def test_new_running_pod_is_not_ready(self):
        pod = {'metadata': {'annotations': {'kubectl.kubernetes.io/restartedAt': 'now'}},
               'status': {'phase': 'Running', 'conditions': [
                   {'type': 'Ready', 'status': 'False', 'message': 'Readiness probe failed'}]}}
        state = pod_state(pod, 'now')
        self.assertTrue(state['is_new'])
        self.assertFalse(state['is_ready'])
        self.assertEqual(state['detail'], 'Readiness probe failed')

    def test_old_ready_pod_and_terminating_pod(self):
        pod = {'metadata': {}, 'status': {'conditions': [{'type': 'Ready', 'status': 'True'}]}}
        self.assertFalse(pod_state(pod, 'now')['is_new'])
        self.assertTrue(pod_state(pod, 'now')['is_ready'])
        pod['metadata']['deletionTimestamp'] = 'now'
        self.assertFalse(pod_state(pod, 'now')['is_ready'])

    def test_init_container_failure(self):
        pod = {'status': {'initContainerStatuses': [{'state': {'waiting': {
            'reason': 'ImagePullBackOff', 'message': 'Unable to pull image'}}}]}}
        state = pod_state(pod, 'now')
        self.assertEqual(state['phase'], 'ImagePullBackOff')
        self.assertEqual(state['detail'], 'Unable to pull image')


class TestStatusAPI(unittest.TestCase):
    def test_new_readiness_excludes_old_pods_and_reports_fetch_errors(self):
        server = SimpleNamespace(current_env='dev', environments={'dev': {'k8s_context': 'test'}})
        client = VaultWebUI(server).app.test_client()
        deploy = _deploy(updated=1)
        deploy['spec'].update({'selector': {'matchLabels': {'app': 'test'}},
                              'template': {'metadata': {'annotations': {
                                  'kubectl.kubernetes.io/restartedAt': 'now'}}}})
        pods = [{'metadata': {'name': 'old'}, 'status': {'conditions': [
            {'type': 'Ready', 'status': 'True'}]}},
            {'metadata': {'name': 'new', 'annotations': {
                'kubectl.kubernetes.io/restartedAt': 'now'}},
             'status': {'conditions': [{'type': 'Ready', 'status': 'False'}]}}]
        def result(data, code=0):
            return SimpleNamespace(returncode=code, stdout=json.dumps(data), stderr='Forbidden' if code else '')
        with patch('vault_mcp.web_ui.subprocess.run', side_effect=[result(deploy), result({'items': pods})]):
            state = client.get('/api/k8s/deployments/status?namespace=default&name=test').json['status']
        self.assertEqual(state['new_ready'], 0)
        self.assertFalse(state['pods'][0]['is_new'])
        self.assertTrue(state['pods'][1]['is_new'])
        with patch('vault_mcp.web_ui.subprocess.run', side_effect=[result(deploy), result({}, 1)]):
            state = client.get('/api/k8s/deployments/status?namespace=default&name=test').json['status']
        self.assertIsNone(state['new_ready'])
        self.assertEqual(state['pods_error'], 'Forbidden')


class TestK8sNameValidation(unittest.TestCase):
    def test_valid_names(self):
        for name in ['nginx', 'my-app-v2', 'a', 'app.web', 'kube-system']:
            self.assertIsNotNone(K8S_NAME_RE.match(name), name)

    def test_invalid_names(self):
        for name in ['', '-leading', 'trailing-', 'UPPER', 'has space',
                     'semi;colon', 'a/b', '$(rm -rf)', 'name"quote']:
            self.assertIsNone(K8S_NAME_RE.match(name), name)


if __name__ == '__main__':
    unittest.main()
