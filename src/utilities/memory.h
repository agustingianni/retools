#ifndef MEMORY_H_
#define MEMORY_H_

// Workaround for the lack of std::make_unique.
namespace std {
template <typename T, typename... Args>
std::unique_ptr<T> make_unique(Args&&... args)
{
    return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}
}

#endif /* MEMORY_H_ */