#include <stdlib.h>
#include "Structs.h"

#pragma region mem.c

static void* (__cdecl* malloc_func) (size_t) = malloc;
static void* __cdecl default_malloc_ex(size_t num, const char* file, int line)
{
	return malloc_func(num);
}

static void* (__cdecl* realloc_func) (void*, size_t) = realloc;
static void* __cdecl default_realloc_ex(void* str, size_t num,
	const char* file, int line)
{
	return realloc_func(str, num);
}

static void* (__cdecl* malloc_ex_func) (size_t, const char* file, int line)
= default_malloc_ex;

static void* (__cdecl* realloc_ex_func) (void*, size_t, const char* file, int line)
= default_realloc_ex;

static void(__cdecl* free_func) (void*) = free;

#if 0
void CRYPTO_get_mem_functions(void* (**m) (size_t),
	void* (**r) (void*, size_t),
	void (**f) (void*))
#else
void CRYPTO_get_mem_functions(void* (__cdecl** m) (size_t),
	void* (__cdecl** r) (void*, size_t),
	void(__cdecl** f) (void*))
#endif // 1
{
	if (m != NULL)
		* m = (malloc_ex_func == default_malloc_ex) ? malloc_func : 0;
	if (r != NULL)
		* r = (realloc_ex_func == default_realloc_ex) ? realloc_func : 0;
	if (f != NULL)
		* f = free_func;
}

#pragma endregion // mem.c

static int dynamic_load(ENGINE* e, dynamic_data_ctx* ctx)
{
	dynamic_fns fns;

	CRYPTO_get_mem_functions(&fns.mem_fns.malloc_cb,
		&fns.mem_fns.realloc_cb, &fns.mem_fns.free_cb);

	return 1;
}

int __cdecl main()
{
}
