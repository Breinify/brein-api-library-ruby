# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'Breinify/version'

Gem::Specification.new do |spec|
  spec.name          = "Breinify"
  spec.version       = Breinify::VERSION
  spec.authors       = ["Breinify, Marco Recchioni"]
  spec.email         = ["marco.recchioni@breinify.com"]

  spec.summary       = %q{Breinify´s DigitalDNA API puts dynamic behavior-based, people-driven data right at your fingertips.}
  spec.description   = %q{Breinifys DigitalDNA API puts dynamic behavior-based, people-driven data right at your fingertips. We believe that in many situations, a critical component of a great user experience is personalization. With all the data available on the web it should be easy to provide a unique experience to every visitor, and yet, sometimes you may find yourself wondering why it is so difficult..}
  spec.homepage      = 'http://www.breinfiy.com'
  spec.license       = 'MIT'

  # Prevent pushing this gem to RubyGems.org. To allow pushes either set the 'allowed_push_host'
  # to allow pushing to a single host or delete this section to allow pushing to any host.
  #if spec.respond_to?(:metadata)
  #  spec.metadata['allowed_push_host'] = 'https://rubygems.org'
  #else
  #  raise "RubyGems 2.0 or newer is required to protect against " \
  #    "public gem pushes."
  #end

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.13"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec", "~> 3.1.0"

end
