# frozen_string_literal: true

Gem::Specification.new do |spec|
  spec.name = "pii_shield"
  spec.version = "0.1.0"
  spec.authors = ["Jotara Lab"]
  spec.email = ["inquiries@jotaralab.com"]
  spec.summary = "Sub-millisecond PII redaction & reversible pseudonymization for AI agents (Ruby bindings)."
  spec.description = "Ruby bindings for pii-shield via the libpii_ffi C-ABI. Leak-free string lifecycle, AutoPointer for native vault handles."
  spec.homepage = "https://github.com/jotaralab/pii-shield"
  spec.license = "Apache-2.0 OR MIT"
  spec.required_ruby_version = ">= 3.0"

  spec.add_dependency("ffi", ["~> 1.16"])

  spec.files = Dir["lib/**/*.rb"]
  spec.require_paths = ["lib"]
  spec.metadata["source_code_uri"] = "https://github.com/jotaralab/pii-shield"
end
