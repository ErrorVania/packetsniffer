#pragma once

#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <iostream>


//writes and returns index of interface into ifstr
int getIfaceIndex(int sock, const char* ifacename, ifreq* ifstr);
void getIfaceFlags(int sock, ifreq* ifstr);
void setIfaceFlags(int sock, ifreq* ifstr);
void getIfaceMAC(int sock, ifreq* ifstr);
void BindToInterface(int sock, ushort fam, ushort proto, int idex);