#!/bin/sh
echo "Before rmmod"
lsmod | grep sys_xintegrity

rmmod sys_xintegrity
echo $'\n'
insmod sys_xintegrity.ko

echo "After insmod"
lsmod | grep sys_xintegrity
