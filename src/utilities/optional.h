#ifndef OPTIONAL_H_
#define OPTIONAL_H_

#include <optional/optional.hpp>

// Workaround for the lack of std::optional.
namespace std {
template <typename T>
using optional = std::experimental::optional<T>;
}

#endif /* OPTIONAL_H_ */
