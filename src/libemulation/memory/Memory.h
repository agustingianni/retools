#ifndef SRC_LIBEMULATION_MEMORY_MEMORY_H_
#define SRC_LIBEMULATION_MEMORY_MEMORY_H_

#include <list>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <sys/mman.h>

#define PAGE_SIZE 0x1000
#define PAGE_MASK (PAGE_SIZE - 1)
#define PAGE_ALIGNED(x) (((x) & PAGE_MASK) == 0)
#define PAGE_ALIGN(x) (((x) + PAGE_SIZE - 1) & PAGE_MASK)

namespace Memory {

	struct Segment {
		Segment() = default;

		Segment(uintptr_t address, size_t size, unsigned prot, void *data) :
				m_data { data },
				m_start { address },
				m_end { address + size },
				m_size { size },
				m_prot { prot } {
		}

		// Checks if the segment contains the address.
		bool contains(uintptr_t address) const {
			return address >= m_start && address < m_end;
		}

		// Checks if the segment contains the whole range.
		bool contains(uintptr_t address, size_t size) const {
			return contains(address) && contains(address + size);
		}

		// Check if the address range overlaps with the segment.
		bool overlaps(uintptr_t address, size_t size) const {
			return contains(address) || contains(address + size)
					|| contains(address, size);
		}

		void *pointer(uintptr_t address) {
			unsigned char *tmp = reinterpret_cast<unsigned char *>(m_data) + (address - m_start);
			return reinterpret_cast<void *>(tmp);
		}

		void *m_data;
		uintptr_t m_start;
		uintptr_t m_end;
		size_t m_size;
		unsigned m_prot;
	};

	class SegmentManager {
	private:
		std::list<Segment> m_segments;
		Segment m_lru_seg;

	public:
		bool overlaps(unsigned address, size_t size) const {
			bool ret = false;
			for (const auto &segment : m_segments) {
				if (segment.overlaps(address, size)) {
					ret = true;
					break;
				}
			}

			return ret;
		}

		bool removeSegment(uintptr_t address, size_t size) {
			// TODO: Implement.
			return true;
		}

		bool protectSegment(uintptr_t address, size_t size, unsigned prot) {
			// TODO: Implement.
			return true;
		}

		bool addSegment(uintptr_t address, size_t size, unsigned prot) {
			prot = PROT_READ | PROT_WRITE;
			void *data = mmap(nullptr, size, prot, MAP_ANON | MAP_PRIVATE, 0, 0);
			if (data == MAP_FAILED) {
				printf("Failed allocate memory with mmap\n");
				return false;
			}

			Segment segment { address, size, prot, data };
			m_segments.push_back(segment);

			return true;
		}

		bool getSegment(uintptr_t address, Segment &segment) {
			if (m_lru_seg.contains(address)) {
				segment = m_lru_seg;
				return true;
			}

			auto it = std::find_if(m_segments.begin(), m_segments.end(),
					[=] (const Segment &el) {
						return el.contains(address);
					});

			if (it == m_segments.end()) {
				return false;
			}

			segment = *it;
			m_lru_seg = segment;
			return true;
		}
	};

	class AbstractMemory {
	public:
		AbstractMemory() = default;
		virtual ~AbstractMemory() = default;

		virtual bool protect(uintptr_t address, size_t size, unsigned prot) = 0;
		virtual bool unmap(uintptr_t address, size_t size) = 0;
		virtual bool map(uintptr_t address, size_t size, unsigned prot) = 0;

		virtual size_t read(uintptr_t address, void *buffer, size_t size) = 0;
		virtual size_t write(uintptr_t address, const void *buffer, size_t size) = 0;

		template<typename T> size_t read_value(uintptr_t address, T &value) {
			return read(address, reinterpret_cast<void *>(&value), sizeof(T));
		}

		template<typename T> size_t write_value(uintptr_t address, const T &value) {
			return write(address, reinterpret_cast<const void *>(&value), sizeof(T));
		}
	};

	class ConcreteMemory: public AbstractMemory {
	private:
		SegmentManager m_segments;

	public:
		ConcreteMemory() = default;
		virtual ~ConcreteMemory() = default;

		bool protect(uintptr_t address, size_t size, unsigned prot) override {
			if (!size) {
				printf("Cannot protect an empty segment.\n");
				return false;
			}

			if (!PAGE_ALIGNED(address)) {
				printf("Cannot protect a non page aligned segment.\n");
				return false;
			}

			if (!PAGE_ALIGNED(size)) {
				size = PAGE_ALIGN(size);
			}

			return true;
		}

		bool unmap(uintptr_t address, size_t size) override {
			return true;
		}

		bool map(uintptr_t address, size_t size, unsigned prot) override {
			printf("DEBUG: map -> address=0x%.8x size=0x%.8x prot=0x%.8x\n",
					address, size, prot);

			if (!size) {
				printf("Cannot map an empty segment.\n");
				return false;
			}

			if (!PAGE_ALIGNED(address)) {
				printf("Cannot map a non page aligned segment.\n");
				return false;
			}

			if (!PAGE_ALIGNED(size)) {
				size = PAGE_ALIGN(size);
			}

			if (m_segments.overlaps(address, size)) {
				printf("Cannot map segment that overlaps.\n");
				return false;
			}

			if (!m_segments.addSegment(address, size, prot)) {
				printf("Cannot map segment.\n");
				return false;
			}

			return true;
		}

		size_t read(uintptr_t address, void *buffer, size_t size) override {
			printf("DEBUG: read -> address=0x%.8x buffer=%p size=0x%.8x\n", address, buffer, size);

			Segment segment;
			if (!m_segments.getSegment(address, segment)) {
				printf("Failed to read at address 0x%.8x\n", address);
				return 0;
			}

			memcpy(buffer, segment.pointer(address), size);
			return size;
		}

		size_t write(uintptr_t address, const void *buffer, size_t size) override {
			printf("DEBUG: write -> address=0x%.8x buffer=%p size=0x%.8x\n", address, buffer, size);

			Segment segment;
			if (!m_segments.getSegment(address, segment)) {
				printf("Failed to write at address 0x%.8x\n", address);
				return 0;
			}

			memcpy(segment.pointer(address), buffer, size);
			return size;
		}
	};

	class ZeroMemoryMap: public AbstractMemory {
	public:
		ZeroMemoryMap() = default;
		~ZeroMemoryMap() = default;

		bool protect(uintptr_t address, size_t size, unsigned prot) override {
			return true;
		}

		bool unmap(uintptr_t address, size_t size) override {
			return true;
		}

		bool map(uintptr_t address, size_t size, unsigned prot) override {
			return true;
		}

		size_t read(uintptr_t address, void *buffer, size_t size) override {
			memset(buffer, 0, size);
			return size;
		}

		size_t write(uintptr_t address, const void *buffer, size_t size) override {
			return size;
		}
	};
}

#endif /* SRC_LIBEMULATION_MEMORY_MEMORY_H_ */
