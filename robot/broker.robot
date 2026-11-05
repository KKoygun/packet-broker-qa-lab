*** Settings ***
Documentation     Acceptance checks written so a non-programmer can read them.
Library           BrokerLibrary.py

*** Test Cases ***
Mirror Copies Every Frame
    Create Broker
    Send Frames    10
    Monitor Port Should Have    10
    Counter Should Be    rx_frames    10

VLAN Filter Keeps Only The Allowed VLAN
    Create Broker    10
    Send Frames    3    vlan=10
    Send Frames    2    vlan=20
    Monitor Port Should Have    3
    Counter Should Be    filtered_vlan    2

Runt Frame Is Dropped And Counted
    Create Broker
    Send Runt Frame
    Monitor Port Should Have    0
    Counter Should Be    dropped_runt    1

Mirror Works Over Real Veth Pairs
    [Tags]    netns
    Skip Without Privileges
    Start Lab
    Create Broker
    Send Frames Through Lab    5
    Monitor Namespace Should Have    5
    [Teardown]    Stop Lab
