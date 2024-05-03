# Runs only once before every test
setup_file() {
    load 'test_helper/common_setup'
    load 'test_helper/common_teardown'

    _common_setup
    _run_kernel_modul_without_ktls
    _run_file_server
    _run_file_server_with_TLS
    _run_file_server_with_TLS_for_passtrhough
    _run_nginx_in_docker
}
# Runs before every test
# setup() {

# }
@test "test file-server with TLS" {
    # run echo "Test a normal directory listing with wget"
    # run wget -d http://localhost:8000/ -O /dev/null
    # assert_success

    # run echo "Test downloading a bigger file with curl"
    # head -c 2M </dev/urandom > bigfile.o
    # assert_success
    # curl -v -o /tmp/bigfile_downloaded.o http://localhost:8000/bigfile.o
    # assert_success
    run smoke.sh
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
}