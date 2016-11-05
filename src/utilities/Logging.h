/*
 * Logging.h
 *
 *  Created on: Jun 29, 2013
 *      Author: anon
 */

#ifndef LOGGING_H_
#define LOGGING_H_

#include <iostream>
#include <sstream>
#include <string>
#include <iomanip>

#define RESET   "\033[0m"
#define BLACK   "\033[30m"      /* Black */
#define RED     "\033[31m"      /* Red */
#define GREEN   "\033[32m"      /* Green */
#define YELLOW  "\033[33m"      /* Yellow */
#define BLUE    "\033[34m"      /* Blue */
#define MAGENTA "\033[35m"      /* Magenta */
#define CYAN    "\033[36m"      /* Cyan */
#define WHITE   "\033[37m"      /* White */
#define BOLDBLACK   "\033[1m\033[30m"      /* Bold Black */
#define BOLDRED     "\033[1m\033[31m"      /* Bold Red */
#define BOLDGREEN   "\033[1m\033[32m"      /* Bold Green */
#define BOLDYELLOW  "\033[1m\033[33m"      /* Bold Yellow */
#define BOLDBLUE    "\033[1m\033[34m"      /* Bold Blue */
#define BOLDMAGENTA "\033[1m\033[35m"      /* Bold Magenta */
#define BOLDCYAN    "\033[1m\033[36m"      /* Bold Cyan */
#define BOLDWHITE   "\033[1m\033[37m"      /* Bold White */

enum LogLevel {
    ERROR, WARNING, INFO, SEEME, DEBUG, INVALID
};

static LogLevel DefaultLevel = DEBUG;

static std::string LogLevelToString(LogLevel level) {
    static const char* const buffer[] = { "ERR", "WAR", "INF", "SEE", "DBG","INV" };
    return buffer[level];
}

namespace logger {
    inline void log(LogLevel l, std::string const& msg) {
        if (l <= DefaultLevel) {
            std::cout << "[";

            switch (l) {
                case ERROR:
                    std::cout << BOLDRED;
                    break;

                case WARNING:
                    std::cout << BOLDMAGENTA;
                    break;

                case INFO:
                    std::cout << BOLDBLUE;
                    break;

                case DEBUG:
                    std::cout << BOLDYELLOW;
                    break;

                case SEEME:
                    std::cout << BOLDGREEN;
                    break;

                default:
                    break;
            }

            std::cout << LogLevelToString(l) << RESET << "]: " << msg << "\n";
        }
    }

    inline void setLogLevel(LogLevel level) {
        DefaultLevel = level;
    }
}

#define LOG(Level) scoped_logger(Level).stream()

struct scoped_logger {
        explicit scoped_logger(LogLevel level) :
                _level(level) {
        }

        std::stringstream& stream() {
            return _ss;
        }

        ~scoped_logger() {
            logger::log(_level, _ss.str());
        }

    private:
        std::stringstream _ss;
        LogLevel _level;
};

#endif /* LOGGING_H_ */
