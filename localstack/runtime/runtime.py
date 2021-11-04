from typing import Any

from localstack.aws.app import LocalstackAwsGateway
from localstack.aws.gateway import Gateway
from localstack.services.plugins import ServiceManager, ServicePluginManager

from . import hooks, server


class Runtime:
    config: Any  # currently this is the "localstack.config" module, but should be a dynaconf setings object
    gateway: Gateway
    service_manager: ServiceManager

    def __init__(self, config):
        self.config = config
        self.service_manager = ServicePluginManager()
        self.gateway = LocalstackAwsGateway(self.service_manager)

        # load functional configurator plugins
        self.config_hooks = hooks.HookManager(hooks.NS_CONFIGURE)
        self.startup_hooks = hooks.HookManager(hooks.NS_STARTUP)
        self.shutdown_hooks = hooks.HookManager(hooks.NS_SHUTDOWN)

        self.server_thread = None

    def configure(self):
        self.config_hooks.run_in_order(self)

    def run(self):
        self.server_thread = server.start(
            self.gateway, self.config.EDGE_PORT, self.config.EDGE_BIND_HOST
        )

        self.startup_hooks.run_in_order(self)

        self.server_thread.join()

    def shutdown(self):
        self.shutdown_hooks.run_in_order(self)
        self.server_thread.stop()

    def cleanup(self):
        pass
