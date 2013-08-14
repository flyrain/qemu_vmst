#include "taint.h"
#include "stdio.h"
void  globalTaintInit(UInt start, UInt end)
{
	UInt i;
	

	for(i=start;i<end;i++)
		set_mem_taint(i, TAINTED);
}

int
main()
{
	init_shadow_memory();
	unsigned int i=1;
	globalTaintInit(0xc1480b70, 0xc1744000);
	globalTaintInit(0xc1795200, 0xc179a9c7);
	globalTaintInit(0xc179f000, 0xc18fb000);
	
	while(i!=0){
		scanf("%x", &i);
		printf("%x %d", i, get_mem_taint(i));
	}
}
