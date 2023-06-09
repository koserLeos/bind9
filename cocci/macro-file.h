#define noreturn __attribute__((noreturn))
#define FLARG
#define FLARG_PASS

#define ISC_LIST(type)             \
	struct {                   \
		type *head, *tail; \
	}

#define ISC_LINK(type)             \
	struct {                   \
		type *prev, *next; \
	}
