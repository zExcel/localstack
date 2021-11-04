from typing import List

from plugin import PluginManager

from localstack.aws.app import LocalstackAwsGateway
from localstack.aws.gateway import Gateway
from localstack.services.plugins import ServiceManager, ServicePluginManager

from . import server
from .configure import RuntimeConfigurator


class Runtime:
    configurators: List[RuntimeConfigurator]
    gateway: Gateway
    service_manager: ServiceManager

    def __init__(self, config):
        self.config = config
        self.service_manager = ServicePluginManager()
        self.gateway = LocalstackAwsGateway(self.service_manager)

        self.configurators = PluginManager("localstack.configurators").load_all()

        self.server_thread = None

    def configure(self):
        for configurator in self.configurators:
            configurator(self)

    def run(self):
        self.server_thread = server.start(
            self.gateway, self.config.EDGE_PORT, self.config.EDGE_BIND_HOST
        )
        self.server_thread.join()

    def shutdown(self):
        self.server_thread.stop()

    def cleanup(self):
        pass
