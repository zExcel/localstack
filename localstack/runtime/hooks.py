import functools

from plugin import PluginManager, plugin

# plugin namespace constants
NS_CONFIGURE = "localstack.hooks.configure"
NS_STARTUP = "localstack.hooks.startup"
NS_SHUTDOWN = "localstack.hooks.shutdown"


def hook(namespace: str, priority: int = 0, **kwargs):
    """
    Decorator for creating functional plugins that have a hook_priority attribute.
    """

    def wrapper(fn):
        fn.hook_priority = priority
        return plugin(namespace=namespace, **kwargs)(fn)

    return wrapper


def hook_spec(namespace: str):
    """
    Creates a new hook decorator bound to a namespace.

    myhook = hook_spec("localstack.hooks.myhook")

    @myhook()
    def foo():
        pass
    """
    return functools.partial(hook, namespace=namespace)


class HookManager(PluginManager):
    def load_all_sorted(self, propagate_exceptions=False):
        """
        Loads all hook plugins and sorts them by their hook_priority attribute.
        """
        plugins = self.load_all(propagate_exceptions)
        # the hook_priority attribute is part of the function wrapped in the FunctionPlugin
        plugins.sort(
            key=lambda _fn_plugin: getattr(_fn_plugin.fn, "hook_priority", 0), reverse=True
        )
        return plugins

    def run_in_order(self, *args, **kwargs):
        """
        Loads and runs all plugins in order them with the given arguments.
        """
        for fn_plugin in self.load_all_sorted():
            fn_plugin(*args, **kwargs)


configure = hook_spec(namespace=NS_CONFIGURE)
startup = hook_spec(namespace=NS_STARTUP)
shutdown = hook_spec(namespace=NS_SHUTDOWN)
