#ifndef ZERO_INITIALIZER_H_
#define ZERO_INITIALIZER_H_

// clang-format off

#ifdef __cplusplus
#define ZERO_INITIALIZER                                                      \
	{ }
#elif defined(__clang__)
#define ZERO_INITIALIZER                                                      \
	_Pragma("clang diagnostic push")                                      \
	_Pragma("clang diagnostic ignored \"-Wmissing-field-initializers\"")  \
	{ 0 }                                                                 \
	_Pragma("clang diagnostic pop")
#else
#define ZERO_INITIALIZER                                                      \
	{ 0 }
#endif

// clang-format on

#endif // ZERO_INITIALIZER_H_
