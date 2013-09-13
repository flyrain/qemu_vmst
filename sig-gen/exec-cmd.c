#include "stdio.h"

void main()
{
  char cmd[100];
  sprintf(cmd, "./src/signa -g ./%s 0 0 > allmd5", "name");
  printf("%s", cmd);

  /*
  printf("%s\n", cmd);
  system(cmd);

  sprintf(cmd, "python ./src/match-module.py ./src/sig-md5 allmd5 > output");
  printf("%s\n", cmd);
  system(cmd);
  */
}
