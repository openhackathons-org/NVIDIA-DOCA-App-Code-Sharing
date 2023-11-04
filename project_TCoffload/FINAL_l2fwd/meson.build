project('L2FWD', 'C', 'CPP',
	license: 'BSD',
	default_options: ['buildtype=debug']
)

APP_NAME = 'l2fwd'

cpp_args = [
	'-std=c++11'
]

# Comment this line to restore warnings of experimental DOCA features
add_project_arguments('-D DOCA_ALLOW_EXPERIMENTAL_API', language: 'c')

dependency_libdpdk = dependency('libdpdk', required : false)
if not dependency_libdpdk.found()
	error('Please set PKG_CONFIG_PATH to DPDK packages path, for further instructions please refer to the DOCA Reference Applications guide')
endif
app_dependencies = [dependency_libdpdk]
# app_dependencies += dependency('json-c', required : true)
# app_dependencies += dependency('threads', required : true)
app_dependencies += dependency('doca-argp', required : true)
app_dependencies += dependency('doca-flow', required : true)
app_dependencies += dependency('doca-common', required : true)

common_dir_path = '../common/src'
app_inc_dirs = [include_directories(common_dir_path)]

vanilla_app_srcs = [
	APP_NAME + '.c',
	files(common_dir_path + '/dpdk_utils.c'),
	files(common_dir_path + '/offload_rules.c'),
	files(common_dir_path + '/utils.c'),
]

executable('doca_' + APP_NAME, vanilla_app_srcs,
	cpp_args : cpp_args,
	dependencies : app_dependencies,
	include_directories : app_inc_dirs,
	install: false)
