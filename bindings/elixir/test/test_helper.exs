ExUnit.start()

# Fail loudly if the NIF shim or shared library is missing, but only when a
# native test actually runs (each test guards with native_available?/0).
