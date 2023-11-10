#ifndef ARRAY_H
#define ARRAY_H
#include <stdlib.h>
#include <string.h>
#include <math.h>

typedef struct { size_t size, capacity; } array;

#define max(a, b) (((a) > (b)) ? (a) : (b))
#define array(T) T *
#define arr_data(arr) (((array *) arr) - 1) 
#define arr_new(T, ...) ({                                 \
    T tmp[] = { __VA_ARGS__ };                             \
    array *ptr = malloc(sizeof(array) + max(8*sizeof(T), sizeof(tmp))); \
    *ptr = (array) { sizeof(tmp) / sizeof(T), max(8*sizeof(T), sizeof(tmp)) / sizeof(T) }; \
    (T *) memcpy(++ptr, tmp, sizeof(tmp));                 \
})
#define arr_fill(T, val, len) ({                           \
    array *ptr = malloc(sizeof(array) + len * sizeof(T));  \
    ptr->size = ptr->capacity = len;                       \
    for (size_t i = 0; i < len; ++i)                       \
        ((T *) (ptr + 1))[i] = val;                        \
    (T *) ++ptr;                                           \
})
#define each(item, arr) (typeof(arr) item = arr; item != &arr[len(arr)]; ++item)
#define reversed(item, arr)  (typeof(arr) item = &arr[len(arr)-1]; item != arr - 1; --item)
#define len(arr) ({ arr_data(arr)->size; })
#define cap(arr) ({ arr_data(arr)->capacity; })
#define arr_resize(arr, new_capacity) do {                 \
    arr_data(arr)->capacity = new_capacity;                \
    array *tmp = realloc(arr_data(arr), sizeof(array) + cap(arr)*sizeof(*arr)); \
    arr = (typeof(arr)) (++tmp);                           \
} while (0)
#define arr_insert(arr, i, elem) do {                      \
    if (len(arr) == cap(arr))                              \
        arr_resize(arr, cap(arr) * 2);                     \
    arr[i] = (memmove(arr + i + 1, arr + i, (arr_data(arr)->size++ - i) * sizeof(*arr)), elem); \
} while (0)
#define make_cmp(T) ({                          \
    int __cmp__(const void *a, const void *b) { \
        return (*(T *) a - *(T *) b < 0) ? floor(*(T *) a - *(T *) b) : ceil(*(T *) a - *(T *) b); \
    }                                           \
    __cmp__;                                    \
})
#define sort(arr) qsort(arr, len(arr), sizeof(*arr), make_cmp(typeof(*arr)))
#define binarysearch(arr, value) ({             \
    typeof(*arr) tmp = value;                   \
    bsearch(&tmp, arr, len(arr), sizeof(*arr), make_cmp(typeof(*arr))); \
})
#define arr_push(arr, elem) arr_insert(arr, (len(arr)-1), elem)
#define arr_pop(arr) ({ arr[--arr_data(arr)->size]; })
#define arr_remove_at(arr, i) memmove(arr+(i), arr+(i+1), (--arr_data(arr)->size - (i)) * sizeof(*arr))
#define arr_dest(arr) free(arr_data(arr))
#define arr_qsort(arr, cmp) qsort(arr, len(arr), sizeof(*arr), cmp)
#define arr_bsearch(arr, key, cmp) bsearch(key, arr, len(arr), sizeof(*arr), cmp)
#endif  /* ARRAY_H */