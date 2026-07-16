Feature: The pivot_root_chroot option for chroot isolation

    @pivot_root_chroot
    Scenario: Build succeeds with pivot_root_chroot enabled
        Given an unique mock namespace
        And mock is always executed with "--isolation=simple --config-opts=pivot_root_chroot=True"
        When an online source RPM is rebuilt
        Then the build succeeds

    @pivot_root_chroot
    Scenario: Init and rebuild work with pivot_root_chroot enabled
        Given an unique mock namespace
        And mock is always executed with "--isolation=simple --config-opts=pivot_root_chroot=True"
        And pre-intitialized chroot
        When an online source RPM is rebuilt
        Then the build succeeds

    @pivot_root_chroot
    Scenario: pivot_root_chroot is silently ignored with nspawn isolation
        Given an unique mock namespace
        And mock is always executed with "--config-opts=pivot_root_chroot=True"
        When an online source RPM is rebuilt
        Then the build succeeds

    @pivot_root_chroot
    Scenario: Chroot command works with pivot_root_chroot enabled
        Given an unique mock namespace
        And mock is always executed with "--isolation=simple --config-opts=pivot_root_chroot=True"
        And pre-intitialized chroot
        When a command "echo hello_from_pivot_root" is run in the mock chroot
        Then the exit code is 0
        And stdout contains "hello_from_pivot_root"

    @pivot_root_chroot
    Scenario: User namespace can be created with pivot_root_chroot
        Given an unique mock namespace
        And mock is always executed with "--isolation=simple --config-opts=pivot_root_chroot=True"
        And pre-intitialized chroot
        When a command "unshare --user -- echo user_ns_works" is run in the mock chroot
        Then the exit code is 0
        And stdout contains "user_ns_works"
