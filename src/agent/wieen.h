/*
 * Wieen agent — shared declarations.
 */
#ifndef WIEEN_H
#define WIEEN_H

#define WEIEN_MAX_MESSAGE (64 * 1024)

struct wieen_mbox
{
    volatile unsigned long cmd_len;
    volatile unsigned long status;
    volatile unsigned long result_len;
    volatile unsigned long seq;
    char cmd[WEIEN_MAX_MESSAGE];
    char result[WEIEN_MAX_MESSAGE];
};

/* the mailbox: the host writes commands here and reads results back */
extern struct wieen_mbox wieen_mbox;

/* the state of the thread Roblox is currently executing */
extern void* wieen_current_state;

/* guards against re-entering the tick from a nested interpreter call */
extern volatile int wieen_in_tick;

void wieen_tick(void* state);

#endif /* WIEEN_H */
