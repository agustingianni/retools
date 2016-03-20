/*
 * Library.h
 *
 *  Created on: Mar 20, 2016
 *      Author: anon
 */

#ifndef SRC_LIBBINARY_ABSTRACT_LIBRARY_H_
#define SRC_LIBBINARY_ABSTRACT_LIBRARY_H_

namespace Abstract {

class Library {
private:
    std::string m_path;

public:
    Library(std::string path) :
        m_path { path } {

    }

    std::string getPath() const {
        return m_path;
    }

    std::string getName() const {
        std::string base_filename = m_path;
        if (auto idx = m_path.find_last_of("/\\")) {
            base_filename = m_path.substr(idx + 1);
        }

        return base_filename;
    }
};

}

#endif /* SRC_LIBBINARY_ABSTRACT_LIBRARY_H_ */
