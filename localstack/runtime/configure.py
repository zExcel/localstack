import os

from localstack import config

from . import hooks


@hooks.configure(priority=100)
def configure_logging(_runtime):
    print("configure logging")
    from localstack.utils.bootstrap import setup_logging

    setup_logging()


@hooks.configure(should_load=lambda: config.is_env_true("DEBUG"))
def configure_debug(_runtime):
    print("you're running in debug mode!")


@hooks.configure()
def configure_aws_env(_runtime):
    print("aws")
    from localstack.utils.aws import aws_stack

    aws_stack.inject_region_into_env(os.environ, os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
    aws_stack.inject_test_credentials_into_env(os.environ)
