/**************************************************************************************************
 *
 * $File Identification                    $
 * $Filename          : ERP_int.c          $
 * $Module version    : FF.FF.01.01        $
 * $Module name       : ERP                $
 * $Release Date      : DD.MM.YYYY         $
 *
 * Author             : Chris Cracknell
 *
 * Description        : Implementation of internal functions
 *						This module implements the IBM eRezept custom HSM firmware
 *
 **************************************************************************************************/
#include <stdio.h>
#include <string.h>

#include <cryptoserversdk/load_store.h>
#include <cryptoserversdk/os_mem.h>
#include <cryptoserversdk/os_log.h>

#include "ERP.h"
#include "ERP_InternalGlue.h"


unsigned int DumpHSMMemory(void)
{
	unsigned int err = E_ERP_SUCCESS;
	T_OS_MEM_INFO memInfo;

	err = os_mem_info(OS_MEM_TYPE_SECURE, &memInfo);
	T_OS_MEM_BLOCK* pMemBlocks = NULL;
	if (err == E_ERP_SUCCESS)
	{
		os_log_print("Memory Info:\n   Used Blocks: %d, Used Bytes: %d, Free Blocks: %d, Free Bytes: %d, Free Largest Area: %d \n", memInfo.used_blocks, memInfo.used_bytes, memInfo.free_blocks, memInfo.free_bytes, memInfo.free_largest_area);
		pMemBlocks = os_mem_new_tag(sizeof(T_OS_MEM_BLOCK) * (memInfo.used_blocks + 2), OS_MEM_TYPE_SECURE, __FILE__, __LINE__);
		CHECK_NOT_NULL(err, pMemBlocks, 0x3a);
	}
	unsigned int tracedBlocks = 0;
	if (err == E_ERP_SUCCESS)
	{
		os_mem_clr(pMemBlocks, (memInfo.used_blocks + 2));
		err = os_mem_trace(pMemBlocks, memInfo.used_blocks + 2, &tracedBlocks);
	}
	if (err == E_ERP_SUCCESS)
	{
		os_log_print("Tracing Allocated Memory Blocks: \n");
		os_log_print(" Size SD, Size ID, Tag, File, Line\n");
        unsigned int i;
        for (i = 0; i < tracedBlocks; i++)
		{
			os_log_print("  %8d    %8d    %4d    %80s   %4d\n",
				pMemBlocks[i].size[0],
				pMemBlocks[i].size[1],
				pMemBlocks[i].tag,
				pMemBlocks[i].file,
				pMemBlocks[i].line);
		}
	}
	if (pMemBlocks != NULL)
	{
		os_mem_del_set(pMemBlocks, 0);
	}
	return err;
}