import functools
import os
from typing import Callable, Union

from plugin import Plugin, PluginSpec

RuntimeConfigurator = Callable[["Runtime"], None]


class FunctionPlugin(Plugin):
    fn: Callable

    def __init__(
        self,
        fn: Callable,
        should_load: Union[bool, Callable[[], bool]] = None,
        load: Callable = None,
    ) -> None:
        super().__init__()
        self.fn = fn
        self._should_load = should_load
        self._load = load

    def __call__(self, *args, **kwargs):
        return self.fn(*args, **kwargs)

    def load(self, *args, **kwargs):
        if self._load:
            return self._load(*args, **kwargs)

    def should_load(self) -> bool:
        if self._should_load:
            if type(self._should_load) == bool:
                return self._should_load
            else:
                return self._should_load()

        return True


def pluggable(
    namespace, name=None, should_load: Union[bool, Callable[[], bool]] = None, load: Callable = None
):
    def wrapper(fn):
        plugin_name = name or fn.__name__

        # this causes the plugin framework to point the entrypoint to the original function rather than the
        # nested factory function (which would not be resolvable)
        @functools.wraps(fn)
        def factory():
            plugin = FunctionPlugin(fn, should_load=should_load, load=load)
            plugin.namespace = namespace
            plugin.name = plugin_name
            return plugin

        # at discovery-time the factory will point to the method being decorated, and at load-time the factory from
        # this spec instance be used instead of the one being created
        fn.__pluginspec__ = PluginSpec(namespace, plugin_name, factory)

        return fn

    return wrapper


configurator = functools.partial(pluggable, namespace="localstack.configurators")


@configurator()
def configure_logging():
    from localstack.utils.bootstrap import setup_logging

    setup_logging()


@configurator()
def configure_aws_env():
    from localstack.utils.aws import aws_stack

    aws_stack.inject_region_into_env(os.environ, os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
    aws_stack.inject_test_credentials_into_env(os.environ)
