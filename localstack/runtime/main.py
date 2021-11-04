import localstack.config
from localstack.runtime.runtime import Runtime
from localstack.utils.common import call_safe


def main():
    runtime = Runtime(localstack.config)

    runtime.configure()

    try:
        runtime.run()
    except KeyboardInterrupt:
        pass
    finally:
        call_safe(runtime.shutdown)
        runtime.cleanup()


if __name__ == "__main__":
    main()
