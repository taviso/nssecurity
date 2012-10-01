#ifndef __LOG_H
#define __LOG_H

#ifdef NDEBUG
# define l_debug(format...)
#else
# define l_debug(format...) do {                \
         l_debug_(__FUNCTION__, ## format);     \
     } while (false)
#endif

#define l_message(format...) do {               \
        l_message_(__FUNCTION__, ## format);    \
    } while (false)

#define l_warning(format...) do {               \
        l_warning_(__FUNCTION__, ## format);    \
    } while (false)

#define l_error(format...) do {                 \
        l_error_(__FUNCTION__, ## format);      \
    } while (false)

void l_message_(const char *function, const char *format, ...);
void l_debug_(const char *function, const char *format, ...);
void l_warning_(const char *function, const char *format, ...);
void l_error_(const char *function, const char *format, ...);

#endif
