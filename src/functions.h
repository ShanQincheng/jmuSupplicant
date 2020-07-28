#ifndef FUNCTIONS_
#define FUNCTIONS_

#include <stdint.h>
#include <string.h>

#ifndef __linux
#include <sys/malloc.h>
#else /* BSD System like macOS*/
#include <malloc.h>
#endif

#include <iconv.h>
#include <fcntl.h>
#include <signal.h>
#include <syslog.h>

#include "mentohust_encryption/md5.h"

#include "init.h"
#include "eap_frames_operations.h"



static char* get_md5_digest(const char *str, size_t length);
uint8_t
*calculate_the_eap_md5_value_in_response_md5_challenge_frame(
  const uint8_t id,
  const uint8_t *eap_request_md5_chag_value,
  unsigned int eap_md5_value_size
);
int code_convert(char *from_charset, char *to_charset,
             char *inbuf, size_t inlen, char *outbuf, size_t outlen);
void print_server_info (const uint8_t *frame);
void print_notification_msg(const uint8_t *frame);
//extern void showRuijieMsg(const uint8_t *buf, unsigned bufLen);
int midnight_relogin();
int relogin_when_receive_failure_frame();
void HandleSigalrm(int sig, siginfo_t *siginfo, void *context);
void KeepOnline();
int LockRegister(int fd, int cmd, int type, off_t offset, int whence, off_t len);
pid_t LockTest(int fd, int type, off_t offset, int whence, off_t len);
int KillJMUSupplicant(int exit_flag, int fd, int type, off_t offset, int whence, off_t len);
int initiative_exit_program_with_already_running_check(int exit_flag, int fd, pid_t pid);
static int CleanMemory();

#endif
