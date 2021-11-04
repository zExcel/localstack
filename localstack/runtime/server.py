from localstack.aws.gateway import Gateway


def start(gateway: Gateway, port, bind_address="0.0.0.0", use_ssl=False):
    from localstack.aws.serving.http2_server import LocalstackHttp2Adapter
    from localstack.services.generic_proxy import GenericProxy, install_predefined_cert_if_available
    from localstack.utils.server import http2_server

    ssl_creds = (None, None)
    if use_ssl:
        install_predefined_cert_if_available()
        _, cert_file_name, key_file_name = GenericProxy.create_ssl_cert(serial_number=port)
        ssl_creds = (cert_file_name, key_file_name)

    handler = LocalstackHttp2Adapter(gateway)

    return http2_server.run_server(
        port, bind_address, handler=handler, ssl_creds=ssl_creds, asynchronous=True
    )
