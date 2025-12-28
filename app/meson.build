project('crow_app', 'cpp',
  version: '1.0',
  default_options: ['cpp_std=c++17'])

# Dependencies
openssl = dependency('openssl')
thread_dep = dependency('threads')

# Executable
executable('app',
  'app.cpp',
  dependencies: [openssl, thread_dep],
  include_directories: include_directories('asio-1.36.0/include'))