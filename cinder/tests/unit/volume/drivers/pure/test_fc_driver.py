
from cinder.volume.drivers.pure import fc_driver 
from unittest import mock
from copy import deepcopy
from test_pure import PureBaseSharedDriverTestCase
from cinder.volume.drivers.pure import fc_driver 
from cinder.volume.drivers.pure import base_driver
import sys
import pprint
import json
from cinder.tests.unit import fake_constants as fake




def fake_retry(exceptions, interval=1, retries=3, backoff_rate=2):
    def _decorator(f):
        return f

    return _decorator


patch_retry = mock.patch('cinder.utils.retry', fake_retry)
patch_retry.start()
sys.modules['pypureclient'] = mock.Mock()
from cinder.volume.drivers import pure  # noqa

# Only mock utils.retry for cinder.volume.drivers.pure import
patch_retry.stop()

# This part is copied from the Pure 2.x REST API code


class Parameters(object):
    """A class for static parameter names.

    """
    continuation_token = 'continuation_token'
    filter = 'filter'
    limit = 'limit'
    offset = 'offset'
    sort = 'sort'
    x_request_id = 'x_request_id'


class Headers(object):
    """A class for static header names.

    """
    api_token = 'api-token'
    authorization = 'Authorization'
    x_auth_token = 'x-auth-token'
    x_request_id = 'X-Request-ID'
    x_ratelimit_sec = 'X-RateLimit-Limit-second'
    x_ratelimit_min = 'X-RateLimit-Limit-minute'
    x_ratelimit_remaining_sec = 'X-RateLimit-Remaining-second'
    x_ratelimit_remaining_min = 'X-RateLimit-Remaining-minute'


class ItemIterator(object):
    """An iterator for items of a collection returned by the server.

    """

    def __init__(self, client, api_endpoint, kwargs, continuation_token,
                 total_item_count, items, x_request_id,
                 more_items_remaining=None,
                 response_size_limit=1000):
        """Initialize an ItemIterator.

        Args:
            client (Client): A Pure1 Client that can call the API.
            api_endpoint (function): The function that corresponds to the
                internal API call.
            kwargs (dict): The kwargs of the initial call.
            continuation_token (str): The continuation token provided by the
                server. May be None.
            total_item_count (int): The total number of items available in the
                collection.
            items (list[object]): The items returned from the initial response.
            x_request_id (str): The X-Request-ID to use for all subsequent
                calls.
        """
        self._response_size_limit = response_size_limit
        self._client = client
        self._api_endpoint = api_endpoint
        self._kwargs = kwargs
        self._continuation_token = '\'{}\''.format(continuation_token)
        self._total_item_count = total_item_count
        self._more_items_remaining = more_items_remaining
        self._items = items
        self._x_request_id = x_request_id
        self._index = 0

    def __iter__(self):
        """Creates a new iterator.

        Returns:
            ItemIterator
        """
        return self

    def __next__(self):
        """Get the next item in the collection. If there are no items left to

        get from the last response, it calls the API again to get more items.

        Returns:
            object

        Raises:
            StopIteration: If there are no more items to return, or if there
                was an error calling the API.
        """
        # If we've reached the end of the desired limit, stop
        if Parameters.limit in self._kwargs and \
                self._kwargs.get(Parameters.limit) <= self._index:
            raise StopIteration
        # If we've reached the end of all possible items, stop
        if self._total_item_count is not None and self._total_item_count \
                <= self._index:
            raise StopIteration
        if self._response_size_limit is None:
            item_index = self._index
        else:
            item_index = self._index % self._response_size_limit
        # If we've reached the end of the current collection, get more data
        if item_index == len(self._items):
            if self._more_items_remaining is False:
                raise StopIteration
            self._refresh_data()
        # Return the next item in the current list if possible
        if item_index < len(self._items):
            to_return = self._items[item_index]
            self._index += 1
            return to_return
        # If no new data was given, just stop
        raise StopIteration

    def __len__(self):
        """Get the length of collection. Number of items returned is not

        guaranteed to be the length of collection at the start.

        Returns:
            int
        """
        return self._total_item_count or len(self._items)

    def _refresh_data(self):
        """Call the API to collect more items and updates the internal state.

        Raises:
            StopIteration: If there was an error calling the API.
        """
        # Use continuation token if provided
        if Parameters.continuation_token in self._kwargs:
            self._kwargs[Parameters.continuation_token] = \
                self._continuation_token
        else:  # Use offset otherwise (no continuation token with sorts)
            self._kwargs[Parameters.offset] = len(self._items)
        if self._x_request_id is not None:
            self._kwargs[Parameters.x_request_id] = self._x_request_id
        # Call the API again and update internal state
        response, is_error = self._client._call_api(self._api_endpoint,
                                                    self._kwargs)
        if is_error is True:
            raise StopIteration
        body, _, _ = response
        self._continuation_token = '\'{}\''.format(body.continuation_token)
        self._total_item_count = body.total_item_count
        self._items = body.items


class ResponseHeaders(object):
    """An object that includes headers from the server response.

    """

    def __init__(self, x_request_id, x_ratelimit_limit_second,
                 x_ratelimit_limit_minute, x_ratelimit_remaining_second,
                 x_ratelimit_remaining_minute):
        """Initialize a ResponseHeaders.

        Args:
            x_request_id (str): The X-Request-ID from the client or generated
                by the server.
            x_ratelimit_limit_second (int): The number of requests available
                per second.
            x_ratelimit_limit_minute (int): The number of requests available
                per minute.
            x_ratelimit_remaining_second (int): The number of requests
                remaining in that second.
            x_ratelimit_remaining_minute (int): The number of requests
                remaining in that minute.
        """

        self.x_request_id = x_request_id
        self.x_ratelimit_limit_second = x_ratelimit_limit_second
        self.x_ratelimit_limit_minute = x_ratelimit_limit_minute
        self.x_ratelimit_remaining_second = x_ratelimit_remaining_second
        self.x_ratelimit_remaining_minute = x_ratelimit_remaining_minute

    def to_dict(self):
        """Return a dictionary of the class attributes.

        Returns:
            dict
        """

        return self.__dict__

    def __repr__(self):
        """Return a pretty formatted string of the object.

        Returns:
            str
        """

        return pprint.pformat(self.to_dict())


def _create_response_headers(headers):
    response_headers = None
    if headers and headers.get(Headers.x_request_id, None):
        RH = ResponseHeaders(headers.get(Headers.x_request_id, None),
                             headers.get(Headers.x_ratelimit_sec, None),
                             headers.get(Headers.x_ratelimit_min, None),
                             headers.get(Headers.x_ratelimit_remaining_sec,
                                         None),
                             headers.get(Headers.x_ratelimit_remaining_min,
                                         None))
        response_headers = RH
    return response_headers




class Response(object):
    """An abstract response that is extended to a valid or error response.

    """

    def __init__(self, status_code, headers):
        """Initialize a Response.

        Args:
            status_code (int): The HTTP status code.
            headers (dict): Response headers from the server.
        """

        self.status_code = status_code
        self.headers = _create_response_headers(headers)


class ValidResponse(Response):
    """A response that indicates the request was successful and has the

    returned data.
    """

    def __init__(self, status_code, continuation_token, total_item_count,
                 items, headers, total=None, more_items_remaining=None):
        """Initialize a ValidResponse.

        Args:
            status_code (int): The HTTP status code.
            continuation_token (str): An opaque token to iterate over a
                collection of resources. May be None.
            total_item_count (int): The total number of items available in the
                collection.
            items (ItemIterator): An iterator over the items in the collection.
            headers (dict): Response headers from the server.
        """

        super(ValidResponse, self).__init__(status_code, headers)
        self.continuation_token = continuation_token
        self.total_item_count = total_item_count
        self.items = items
        if total is not None:
            self.total = total
        if more_items_remaining is not None:
            self.more_items_remaining = more_items_remaining

    def to_dict(self):
        """Return a dictionary of the class attributes. It will convert the

        items to a list of items by exhausting the iterator. If any items
        were previously iterated, they will be missed.

        Returns:
            dict
        """

        new_dict = dict(self.__dict__)
        if isinstance(self.items, ItemIterator):
            new_dict['items'] = [item.to_dict() for item in list(self.items)]

        new_dict['headers'] = (self.headers.to_dict
                               if self.headers is not None else None)

        if hasattr(self, 'total') and isinstance(self.total, list):
            new_dict['total'] = [item.to_dict() for item in self.total]
        return new_dict

    def __repr__(self):
        """Return a pretty formatted string of the object. Does not convert the

        items to a list of items by using the iterator.

        Returns:
            str
        """

        new_dict = dict(self.__dict__)
        if self.headers:
            new_dict['headers'] = self.headers.to_dict()
        return pprint.pformat(new_dict)


class ErrorResponse(Response):
    """A response that indicates there was an error with the request and has

    the list of errors.
    """

    def __init__(self, status_code, errors, headers):
        """Initialize an ErrorResponse.

        Args:
            status_code (int): The HTTP status code.
            errors (list[ApiError]): The list of errors encountered.
            headers (dict): Response headers from the
                server.
        """

        super(ErrorResponse, self).__init__(status_code,
                                            headers)
        self.errors = errors

    def to_dict(self):
        """Return a dictionary of the class attributes.

        Returns:
            dict
        """

        new_dict = dict(self.__dict__)
        new_dict['errors'] = [err.to_dict() for err in new_dict['errors']]
        new_dict['headers'] = (self.headers.to_dict
                               if self.headers is not None else None)
        return new_dict

    def __repr__(self):
        """Return a pretty formatted string of the object.

        Returns:
            str
        """

        return pprint.pformat(self.to_dict())


# Simple implementation of dot notation dictionary

class DotNotation(dict):

    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__

    def __init__(self, data):
        if isinstance(data, str):
            data = json.loads(data)

        for name, value in data.items():
            setattr(self, name, self._wrap(value))

    def __getattr__(self, attr):
        def _traverse(obj, attr):
            if self._is_indexable(obj):
                try:
                    return obj[int(attr)]
                except Exception:
                    return None
            elif isinstance(obj, dict):
                return obj.get(attr, None)
            else:
                return attr
        # if '.' in attr:
        #    return reduce(_traverse, attr.split('.'), self)
        return self.get(attr, None)

    def _wrap(self, value):
        if self._is_indexable(value):
            # (!) recursive (!)
            return type(value)([self._wrap(v) for v in value])
        elif isinstance(value, dict):
            return DotNotation(value)
        else:
            return value

    @staticmethod
    def _is_indexable(obj):
        return isinstance(obj, (tuple, list, set, frozenset))

    def __deepcopy__(self, memo=None):
        return DotNotation(deepcopy(dict(self), memo=memo))
    


DRIVER_PATH = "cinder.volume.drivers.pure"

FC_DRIVER_OBJ = DRIVER_PATH + ".PureFCDriver"
FC_PORT_NAMES = ["ct0.fc2", "ct0.fc3", "ct1.fc2", "ct1.fc3"]

FC_WWNS = ["21000024ff59fe9" + str(i + 1) for i in range(len(FC_PORT_NAMES))]
AC_FC_WWNS = [
    "21000024ff59fab" + str(i + 1) for i in range(len(FC_PORT_NAMES))]
HOSTNAME = "computenode1"
PURE_HOST_NAME = base_driver.PureBaseVolumeDriver._generate_purity_host_name(HOSTNAME)
PURE_HOST = {
    "name": PURE_HOST_NAME,
    "host_group": None,
    "nqns": [],
    "iqns": [],
    "wwns": [],
}
INITIATOR_WWN = "5001500150015081abc"
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
MANAGEABLE_PURE_VOLS = [
    {
        'name': 'myVol1',
        'id': fake.VOLUME_ID,
        'serial': '8E9C7E588B16C1EA00048CCA',
        'size': 3221225472,
        'provisioned': 3221225472,
        'space': {'total_provisioned': 3221225472},
        'created': '2016-08-05T17:26:34Z',
        'source': None,
        'connection_count': 0
    },
    {
        'name': 'myVol2',
        'id': fake.VOLUME2_ID,
        'serial': '8E9C7E588B16C1EA00048CCB',
        'size': 3221225472,
        'provisioned': 3221225472,
        'space': {'total_provisioned': 3221225472},
        'created': '2016-08-05T17:26:34Z',
        'source': None,
        'connection_count': 0
    },
    {
        'name': 'myVol3',
        'id': fake.VOLUME3_ID,
        'serial': '8E9C7E588B16C1EA00048CCD',
        'size': 3221225472,
        'provisioned': 3221225472,
        'space': {'total_provisioned': 3221225472},
        'created': '2016-08-05T17:26:34Z',
        'source': None,
        'connection_count': 0
    }
]

MPV = ValidResponse(200, None, 3,
                    [DotNotation(MANAGEABLE_PURE_VOLS[0]),
                     DotNotation(MANAGEABLE_PURE_VOLS[1]),
                     DotNotation(MANAGEABLE_PURE_VOLS[2])], {})

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


