#
# Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
#
# This software product is a proprietary product of NVIDIA CORPORATION &
# AFFILIATES (the "Company") and all right, title, and interest in and to the
# software product, including all associated intellectual property rights, are
# and shall remain exclusively with the Company.
#
# This software product is governed by the End User License Agreement
# provided with the software product.
#

project('DOCA_dist_fs', 'C', 'CPP',
	# Get version number from file.
	version: run_command(find_program('cat'),
		files('./VERSION'), check: true).stdout().strip(),
	license: 'Proprietary',
	default_options: ['buildtype=debug'],
	meson_version: '>= 0.61.2'
)

add_project_arguments('-D DOCA_ALLOW_EXPERIMENTAL_API', language: ['c', 'cpp'])

application_name='DOCA_dist_fs'

dependencies = []

# Required for all DOCA programs
dependencies += dependency('doca')
dependencies += dependency('ucx')
dependencies += dependency('glib-2.0')
dependencies += dependency('libbsd')

srcs = [
	# The sample itself
	'c/common.c',
	'c/comm_channel_endpoint.c',
	'c/cmdline_tool.c',
	'c/router_service.c',
	'core/DOCA_dist_fs.cpp',
	# Main
	'tools/' + application_name + '_host_admin_tool.c',
]

inc_dirs  = []

# Core
inc_dirs += include_directories('../core')

executable(application_name + '_host', srcs,
	c_args : '-Wno-missing-braces',
	dependencies : dependencies,
	include_directories: inc_dirs,
	install: false)
