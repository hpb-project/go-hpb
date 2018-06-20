// Copyright 2018 The go-hpb Authors
// This file is part of the go-hpb.
//
// The go-hpb is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-hpb is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-hpb. If not, see <http://www.gnu.org/licenses/>.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include "sha3.h"

#define BUFFER_LEN (8*1024)

typedef struct BoardInfo {
    char board_id[100];
}BoardInfo;

typedef struct MacInfo {
    char mac_list[20][20];
    int  mac_num;
}MacInfo;

static const char *virtual_mac[] = {
    "00:05:69", //vmware1
    "00:0c:29", //vmware2
    "00:50:56", //vmware3
    "00:1c:14", //vmware4
    "00:1c:42", //parallels1
    "00:03:ff", //microsoft virtual 
    "00:0f:4b", //virtual iron 4
    "00:16:3e", //red hat xen, oracle vm, xen source, novell xen
    "08:00:27",  //virtualbox
    NULL
};

static int is_virtual_mac(const char* mac)
{
    int i = 0;
    int isvirtual = 0;
    for (; virtual_mac[i]!=NULL; i++)
    {
        if(strncmp(mac, virtual_mac[i], 8) == 0)
        {
            isvirtual = 1;
            break;
        }
    }
    return isvirtual;
}

static int exec_shell(const char *cmd, char * buff)
{
    memset(buff, 0, BUFFER_LEN);
    FILE *fp = popen(cmd, "r");
    int cnt = 0, redn = 0;
    do{
        cnt += redn;
        redn = fread(buff+cnt, BUFFER_LEN-cnt, 1, fp);
    }while(redn > 0 && (cnt+redn < BUFFER_LEN));
    pclose(fp);
}

static int scan_board(BoardInfo *board, char *cmd_buf)
{
    uid_t uid = getuid();
    if(setuid(0))
    {
        printf("setuid failed.\n");
        return 1;
    }
    memset(board, 0x0, sizeof(*board));
    /* board id */
    exec_shell("dmidecode -s system-serial-number", cmd_buf);
    strcpy(board->board_id, cmd_buf);
    setuid(uid);
    return 0;
}

static int scan_mac(MacInfo *macinfo, char *cmd_buf)
{
    memset(macinfo, 0, sizeof(MacInfo));
    /* mac address */
    int offset = 0;
    char *str1 = NULL, *token = NULL, *saveptr1 = NULL;
    // get all mac addr
    exec_shell("ifconfig -a | grep -v '^docker' | grep -Eo '[0-9a-fA-F]{2,2}:[0-9a-fA-F]{2,2}:[0-9a-fA-F]{2,2}:[0-9a-fA-F]{2,2}:[0-9a-fA-F]{2,2}:[0-9a-fA-F]{2,2}' | sort", cmd_buf);
    for (str1 = cmd_buf; ; str1 = NULL) 
    {
        token = strtok_r(str1, "\n", &saveptr1);
        if (token == NULL)
            break;
        // filter virtual mac.
        if(!is_virtual_mac(token))
        {
            memcpy(macinfo->mac_list[macinfo->mac_num], token, strlen(token));
            macinfo->mac_num++;
        }
    }
    if(macinfo->mac_num <= 0)
    {
        return 1;
    }

    return 0;
}

static int s_general_id(MacInfo *macinfo, BoardInfo *board, char *id)
{
    int datalen = 0;
    for(int i = 0; i < macinfo->mac_num; i++)
    {
        datalen += strlen(macinfo->mac_list[i]);
    }
    datalen += strlen(board->board_id);

    uint8_t *merge_data = (uint8_t*)malloc(datalen);
    memcpy(merge_data, board->board_id, strlen(board->board_id));

    for(int i = 0, offset = strlen(board->board_id); i < macinfo->mac_num; i++)
    {
        memcpy(merge_data+offset, macinfo->mac_list[i], strlen(macinfo->mac_list[i]));
        offset += strlen(macinfo->mac_list[i]);
    }

    uint8_t sha256[32] = {0};
    SHA3_256(sha256, merge_data, datalen);
    for(int i = 0; i < 32; i++)
    {
        sprintf((id)+2*i,"%02x",sha256[i]);
    }
    free(merge_data);

    return 0;
}

int general_id(char *genid)
{
    BoardInfo       board;
    MacInfo         mac;
    char cmd_buf[BUFFER_LEN];
    int ret = 0;
    ret += scan_board(&board, cmd_buf);
    ret += scan_mac(&mac, cmd_buf);
    if(ret == 0)
    {
        ret += s_general_id(&mac, &board, genid);
    }

    return ret;
}
