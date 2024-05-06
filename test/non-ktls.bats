# Runs only once before every test
setup_file() {
    load 'test_helper/common_setup'
    load 'test_helper/common_teardown'

    _common_setup
    _run_kernel_modul_without_ktls
    _run_agent
    _run_file_server
    _run_file_server_with_TLS
    _run_file_server_with_TLS_for_passtrhough
    _run_python_server
    _run_nginx_in_docker
}
# Runs before every test
setup() {
    load 'test_helper/bats-support/load'
    load 'test_helper/bats-assert/load'
}
@test "test file-server with TLS" {
    run test/smoke.sh
    echo "Status received: $status"
    assert_success
}
# Runs after every test
# teardown() {
    
# }
# Runs only once after every test
teardown_file() {
    _teardown_file_server
    _teardown_python_apps
    _teardown_docker_containers
    _teardown_kernel_modul
    _teardown_camblet_agent
}