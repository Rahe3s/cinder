from cinder.volume.drivers.pure import fc_driver 
from unittest import mock
from test_pure import PureBaseSharedDriverTestCase
from cinder.volume.drivers.pure import fc_driver 
from test_pure import ValidResponse,DotNotation,PURE_HOST,INITIATOR_WWN

DRIVER_PATH = "cinder.volume.drivers.pure"

FC_DRIVER_OBJ = DRIVER_PATH + ".PureFCDriver"
FC_PORT_NAMES = ["ct0.fc2", "ct0.fc3", "ct1.fc2", "ct1.fc3"]

FC_WWNS = ["21000024ff59fe9" + str(i + 1) for i in range(len(FC_PORT_NAMES))]
AC_FC_WWNS = [
    "21000024ff59fab" + str(i + 1) for i in range(len(FC_PORT_NAMES))]
HOSTNAME = "computenode1"
PURE_HOST_NAME = pure.PureBaseVolumeDriver._generate_purity_host_name(HOSTNAME)
DRIVER_PATH = "cinder.volume.drivers.pure"
FC_CONNECTOR = {"wwpns": {INITIATOR_WWN}, "host": HOSTNAME}

INITIATOR_TARGET_MAP = {
    # _build_initiator_target_map() calls list(set()) on the list,
    # we must also call list(set()) to get the exact same order
    '5001500150015081abc': list(set(FC_WWNS)),
}
AC_INITIATOR_TARGET_MAP = {
    # _build_initiator_target_map() calls list(set()) on the list,
    # we must also call list(set()) to get the exact same order
    '5001500150015081abc': list(set(FC_WWNS + AC_FC_WWNS)),
}
DEVICE_MAPPING = {
    "fabric": {
        'initiator_port_wwn_list': {INITIATOR_WWN},
        'target_port_wwn_list': FC_WWNS,
    },
}
AC_DEVICE_MAPPING = {
    "fabric": {
        'initiator_port_wwn_list': {INITIATOR_WWN},
        'target_port_wwn_list': FC_WWNS + AC_FC_WWNS,
    },
}
FC_PORTS = [{"name": name,
             "iqn": None,
             "nqn": None,
             "portal": None,
             "wwn": wwn,
             } for name, wwn in zip(FC_PORT_NAMES, FC_WWNS)]
AC_FC_PORTS = [{"name": name,
                "iqn": None,
                "nqn": None,
                "portal": None,
                "wwn": wwn,
                } for name, wwn in zip(FC_PORT_NAMES, AC_FC_WWNS)]

FC_CONNECTION_INFO = {
    "driver_volume_type": "fibre_channel",
    "data": {
        "target_wwn": FC_WWNS,
        "target_wwns": FC_WWNS,
        "target_lun": 1,
        "target_luns": [1, 1, 1, 1],
        "target_discovered": True,
        "addressing_mode": "SAM2",
        "initiator_target_map": INITIATOR_TARGET_MAP,
        "discard": True,
        "wwn": "3624a93709714b5cb91634c470002b2c8",
    },
}
FC_CONNECTION_INFO_AC = {
    "driver_volume_type": "fibre_channel",
    "data": {
        "target_wwn": FC_WWNS + AC_FC_WWNS,
        "target_wwns": FC_WWNS + AC_FC_WWNS,
        "target_lun": 1,
        "target_luns": [1, 1, 1, 1, 5, 5, 5, 5],
        "target_discovered": True,
        "addressing_mode": "SAM2",
        "initiator_target_map": AC_INITIATOR_TARGET_MAP,
        "discard": True,
        "wwn": "3624a93709714b5cb91634c470002b2c8",
    },
}

VALID_FC_PORTS = ValidResponse(200, None, 1,
                               [DotNotation(FC_PORTS[0]),
                                DotNotation(FC_PORTS[1]),
                                DotNotation(FC_PORTS[2]),
                                DotNotation(FC_PORTS[3])], {})

VALID_AC_FC_PORTS = ValidResponse(200, None, 1,
                                  [DotNotation(AC_FC_PORTS[0]),
                                   DotNotation(AC_FC_PORTS[1]),
                                   DotNotation(AC_FC_PORTS[2]),
                                   DotNotation(AC_FC_PORTS[3])], {})

CONNECTION_DATA = {'host': {'name': 'utest'},
                   'host_group': {},
                   'lun': 1,
                   'nsid': 9753,
                   'protocol_endpoint': {},
                   'volume': {'id': '78a9e55b-d9ef-37ce-0dbd-14de74ae35d4',
                              'name': 'xVol1'}}

CONN = ValidResponse(200, None, 1, [DotNotation(CONNECTION_DATA)], {})

AC_CONNECTION_DATA = [{'host': {'name': 'utest5'},
                       'host_group': {},
                       'lun': 5,
                       'nsid': 9755,
                       'protocol_endpoint': {},
                       'volume': {'id': '78a9e55b-d9ef-37ce-0dbd-14de74ae35d5',
                                  'name': 'xVol5'}}]

AC_CONN = ValidResponse(200, None, 1,
                        [DotNotation(AC_CONNECTION_DATA[0])], {})




class PureFCDriverTestCase(PureBaseSharedDriverTestCase):

    def setUp(self):
        super(PureFCDriverTestCase, self).setUp()
        self.driver = fc_driver.PureFCDriver(configuration=self.mock_config)
        self.driver._storage_protocol = "FC"
        self.driver._array = self.array
        self.mock_object(self.driver, '_get_current_array',
                         return_value=self.array)
        self.driver._lookup_service = mock.Mock()

    pure_hosts = ValidResponse(200, None, 1,
                               [DotNotation(PURE_HOST.copy())], {})

    def test_get_host(self):
        good_host = PURE_HOST.copy()
        good_host.update(wwn=["another-wrong-wwn", INITIATOR_WWN])
        pure_bad_host = ValidResponse(200, None, 1,
                                      [], {})
        pure_good_host = ValidResponse(200, None, 1,
                                       [DotNotation(good_host)], {})
        self.array.get_hosts.return_value = pure_bad_host
        actual_result = self.driver._get_host(self.array, FC_CONNECTOR)
        self.assertEqual([], actual_result)
        self.array.get_hosts.return_value = pure_good_host
        actual_result = self.driver._get_host(self.array, FC_CONNECTOR)
        self.assertEqual([good_host], actual_result)
        self.assert_error_propagates([self.array.get_hosts],
                                     self.driver._get_host,
                                     self.array,
                                     FC_CONNECTOR)

    def test_get_host_uppercase_wwpn(self):
        expected_host = PURE_HOST.copy()
        expected_host['wwn'] = [INITIATOR_WWN]
        pure_hosts = ValidResponse(200, None, 1,
                                   [DotNotation(expected_host)], {})
        self.array.get_hosts.return_value = pure_hosts
        connector = FC_CONNECTOR.copy()
        connector['wwpns'] = [wwpn.upper() for wwpn in FC_CONNECTOR['wwpns']]

        actual_result = self.driver._get_host(self.array, connector)
        self.assertEqual([expected_host], actual_result)

    @mock.patch(FC_DRIVER_OBJ + "._get_valid_ports")
    @mock.patch(FC_DRIVER_OBJ + "._get_wwn")
    @mock.patch(FC_DRIVER_OBJ + "._connect")
    def test_initialize_connection(self, mock_connection,
                                   mock_get_wwn, mock_ports):
        vol, vol_name = self.new_fake_vol()
        lookup_service = self.driver._lookup_service
        (lookup_service.get_device_mapping_from_network.
         return_value) = DEVICE_MAPPING
        mock_get_wwn.return_value = '3624a93709714b5cb91634c470002b2c8'
        self.array.get_connections.return_value = CONN.items
        mock_connection.return_value = CONN.items
        mock_ports.return_value = VALID_FC_PORTS.items
        actual_result = self.driver.initialize_connection(vol, FC_CONNECTOR)
        self.assertDictEqual(FC_CONNECTION_INFO, actual_result)

    @mock.patch(FC_DRIVER_OBJ + "._get_valid_ports")
    @mock.patch(FC_DRIVER_OBJ + "._get_wwn")
    @mock.patch(FC_DRIVER_OBJ + "._connect")
    def test_initialize_connection_uniform_ac(self, mock_connection,
                                              mock_get_wwn, mock_ports):
        repl_extra_specs = {
            'replication_type': '<in> sync',
            'replication_enabled': '<is> true',
        }
        vol, vol_name = self.new_fake_vol(type_extra_specs=repl_extra_specs)
        lookup_service = self.driver._lookup_service
        (lookup_service.get_device_mapping_from_network.
         return_value) = AC_DEVICE_MAPPING
        mock_get_wwn.return_value = '3624a93709714b5cb91634c470002b2c8'
        self.array.get_connections.return_value = CONN.items
        self.driver._is_active_cluster_enabled = True
        mock_secondary = mock.MagicMock()
        self.driver._uniform_active_cluster_target_arrays = [mock_secondary]
        mock_secondary.get_connections.return_value = AC_CONN.items
        mock_connection.side_effect = lambda *args, **kwargs: \
            CONN.items if args and args[0] == self.array else AC_CONN.items
        mock_ports.side_effect = lambda *args, **kwargs: \
            VALID_FC_PORTS.items if args and args[0] == self.array \
            else VALID_AC_FC_PORTS.items
        actual_result = self.driver.initialize_connection(vol, FC_CONNECTOR)
        self.assertDictEqual(FC_CONNECTION_INFO_AC, actual_result)

    @mock.patch(DRIVER_PATH + ".flasharray.HostPatch")
    @mock.patch(DRIVER_PATH + ".flasharray.HostPost")
    @mock.patch(FC_DRIVER_OBJ + "._get_host", autospec=True)
    @mock.patch(FC_DRIVER_OBJ + "._generate_purity_host_name", spec=True)
    def test_connect(self, mock_generate,
                     mock_host, mock_post_host,
                     mock_patch_host):
        vol, vol_name = self.new_fake_vol()

        # Branch where host already exists
        pure_hosts = ValidResponse(200, None, 1,
                                   [DotNotation(PURE_HOST.copy())], {})
        mock_host.return_value = pure_hosts.items
        self.array.get_connections.return_value = CONN
        self.array.post_connections.return_value = CONN
        real_result = self.driver._connect(self.array, vol_name, FC_CONNECTOR)
        self.assertEqual([CONNECTION_DATA], real_result)
        mock_host.assert_called_with(self.driver, self.array, FC_CONNECTOR,
                                     remote=False)
        self.assertFalse(mock_generate.called)
        self.assertFalse(self.array.create_host.called)
        self.array.post_connections.\
            assert_called_with(host_names=[PURE_HOST_NAME],
                               volume_names=[vol_name])

        # Branch where new host is created
        empty_hosts = ValidResponse(200, None, 1,
                                    [], {})
        mock_host.return_value = empty_hosts.items
        mock_generate.return_value = PURE_HOST_NAME
        real_result = self.driver._connect(self.array, vol_name, FC_CONNECTOR)
        mock_host.assert_called_with(self.driver, self.array, FC_CONNECTOR,
                                     remote=False)
        mock_generate.assert_called_with(HOSTNAME)
        self.array.post_hosts.assert_called_with(names=[PURE_HOST_NAME],
                                                 host=mock_post_host())
        self.assertEqual([CONNECTION_DATA], real_result)

        mock_generate.reset_mock()
        self.array.reset_mock()
        self.assert_error_propagates(
            [mock_host, mock_generate, self.array.post_connections,
             self.array.post_hosts],
            self.driver._connect, self.array, vol_name, FC_CONNECTOR)

        self.mock_config.safe_get.return_value = 'oracle-vm-server'

        # Branch where personality is set
        self.driver._connect(self.array, vol_name, FC_CONNECTOR)
        self.assertEqual([CONNECTION_DATA], real_result)
        self.array.patch_hosts.\
            assert_called_with(names=[PURE_HOST_NAME],
                               host=mock_patch_host(personality=
                                                    'oracle-vm-server'))

    @mock.patch(DRIVER_PATH + ".LOG")
    @mock.patch(FC_DRIVER_OBJ + "._get_host", autospec=True)
    def test_connect_already_connected(self, mock_host, mock_logger):
        vol, vol_name = self.new_fake_vol()
        hosts = deepcopy(PURE_HOST)
        hosts['name'] = 'utest'
        pure_hosts = ValidResponse(200, None, 1,
                                   [DotNotation(hosts)], {})
        mock_host.return_value = pure_hosts.items
        vdict = {'id': '1e5177e7-95e5-4a0f-b170-e45f4b469f6a',
                 'name': 'volume-1e5177e7-95e5-4a0f-b170-e45f4b469f6a-cinder'}
        NCONNECTION_DATA = {'host': {'name': 'utest'},
                            'host_group': {},
                            'lun': 1,
                            'nsid': None,
                            'protocol_endpoint': {},
                            'volume': vdict}
        NCONN = ValidResponse(200, None, 1,
                              [DotNotation(NCONNECTION_DATA)], {})
        self.array.get_connections.return_value = NCONN
        pure_vol_copy = deepcopy(MANAGEABLE_PURE_VOLS)
        MPV = ValidResponse(200, None, 3,
                            [DotNotation(pure_vol_copy[0]),
                             DotNotation(pure_vol_copy[1]),
                             DotNotation(pure_vol_copy[2])], {})
        self.array.get_volumes.return_value = MPV
        err_rsp = ErrorResponse(400, [DotNotation({'message':
                                'already exists'})], {})
        self.array.post_connections.return_value = err_rsp
        actual = self.driver._connect(self.array, vol_name, FC_CONNECTOR)
        mock_logger.debug.\
            assert_called_with('Volume connection already exists for Purity '
                               'host with message: %s',
                               'already exists')
        self.assertEqual(NCONN.items, actual)
        self.assertTrue(self.array.post_connections.called)
        self.assertTrue(bool(self.array.get_connections))

    @mock.patch(FC_DRIVER_OBJ + "._get_host", autospec=True)
    def test_connect_already_connected_list_hosts_empty(self, mock_host):
        vol, vol_name = self.new_fake_vol()
        pure_hosts = ValidResponse(200, None, 1,
                                   [DotNotation(PURE_HOST)], {})
        mock_host.return_value = pure_hosts.items
        self.array.get_volumes.return_value = MPV
        err_rsp = ErrorResponse(400, [DotNotation({'message':
                                'unknown'})], {})
        self.array.get_connections.return_value = CONN
        self.array.post_connections.return_value = err_rsp
        self.assertRaises(pure.PureDriverException, self.driver._connect,
                          self.array, vol_name, FC_CONNECTOR)
        self.assertTrue(self.array.post_connections.called)
        self.assertTrue(bool(self.array.get_connections))

    @mock.patch(FC_DRIVER_OBJ + "._get_host", autospec=True)
    def test_connect_already_connected_list_hosts_exception(self, mock_host):
        vol, vol_name = self.new_fake_vol()
        hosts = deepcopy(PURE_HOST)
        hosts['name'] = 'utest'
        pure_hosts = ValidResponse(200, None, 1,
                                   [DotNotation(hosts)], {})
        mock_host.return_value = pure_hosts.items
        err_rsp = ErrorResponse(400, [DotNotation({'message':
                                'Unknown Error'})], {})
        self.array.get_connections.return_value = CONN
        self.array.post_connections.return_value = err_rsp
        self.assertRaises(pure.PureDriverException,
                          self.driver._connect, self.array, vol_name,
                          FC_CONNECTOR)
        self.assertTrue(self.array.post_connections.called)
        self.assertTrue(bool(self.array.get_connections))

    @mock.patch(FC_DRIVER_OBJ + "._get_host", autospec=True)
    def test_connect_wwn_already_in_use(self, mock_host):
        vol, vol_name = self.new_fake_vol()
        mock_host.return_value = []

        err_rsp = ErrorResponse(400, [DotNotation({'message':
                                'already in use'})], {})
        self.array.post_hosts.return_value = err_rsp

        # Because we mocked out retry make sure we are raising the right
        # exception to allow for retries to happen.
        self.assertRaises(pure.PureRetryableException,
                          self.driver._connect,
                          self.array, vol_name, FC_CONNECTOR)

    @mock.patch(FC_DRIVER_OBJ + "._disconnect")
    def test_terminate_connection_uniform_ac(self, mock_disconnect):
        repl_extra_specs = {
            'replication_type': '<in> sync',
            'replication_enabled': '<is> true',
        }
        vol, vol_name = self.new_fake_vol(type_extra_specs=repl_extra_specs)
        fcls = self.driver._lookup_service
        fcls.get_device_mapping_from_network.return_value = AC_DEVICE_MAPPING
        self.driver._is_active_cluster_enabled = True
        mock_secondary = mock.MagicMock()
        self.driver._uniform_active_cluster_target_arrays = [mock_secondary]
        self.array.get_ports.return_value = FC_PORTS
        mock_secondary.list_ports.return_value = AC_FC_PORTS
        mock_disconnect.return_value = False

        self.driver.terminate_connection(vol, FC_CONNECTOR)
        mock_disconnect.assert_has_calls([
            mock.call(mock_secondary, vol, FC_CONNECTOR,
                      is_multiattach=False, remove_remote_hosts=True),
            mock.call(self.array, vol, FC_CONNECTOR,
                      is_multiattach=False, remove_remote_hosts=False)
        ])


