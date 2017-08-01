// Copyright (c) 2017 Agustin Gianni
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

// https://github.com/stormbrew/channel9/blob/master/src/libc9/script/parser.cpp
// https://github.com/wisk/medusa/blob/dev/src/core/expression_parser.cpp

#include <string>
#include <vector>
#include <iostream>
#include <tao/pegtl.hpp>
#include <tao/pegtl/analyze.hpp>

namespace pegtl = tao::TAOCPP_PEGTL_NAMESPACE;

struct ASTNode {
    virtual std::string toString() const = 0;
};

struct CommentNode : public ASTNode {
    CommentNode(std::string content)
        : m_content(content)
    {
    }

    std::string toString() const override
    {
        return "<CommentNode: m_content=" + m_content + ">";
    }

    std::string m_content;
};

// clang-format off

// Tokens.
struct LPAR           : pegtl::one<'('> {};
struct RPAR           : pegtl::one<')'> {};
struct LBRACK         : pegtl::one<'['> {};
struct RBRACK         : pegtl::one<']'> {};
struct LBRACE         : pegtl::one<'{'> {};
struct RBRACE         : pegtl::one<'}'> {};
struct SEMI           : pegtl::one<';'> {};
struct COMMA          : pegtl::one<','> {};
struct COLON          : pegtl::one<':'> {};
struct EQUALS         : pegtl::one<'='> {};
struct LANGLE         : pegtl::one<'<'> {};
struct RANGLE         : pegtl::one<'>'> {};
struct DOT            : pegtl::one<'.'> {};
struct QUOTE          : pegtl::one<'\'', '\"'> {};

// Unary operators.
struct unary_minus    : pegtl::one<'-'> {};
struct unary_plus     : pegtl::one<'+'> {};
struct unary_negate   : pegtl::one<'!'> {};
struct unary_invert   : pegtl::one<'~'> {};

// Binary operators.
struct binary_plus        : TAOCPP_PEGTL_STRING("+") {};
struct binary_minus       : TAOCPP_PEGTL_STRING("-") {};
struct binary_mul         : TAOCPP_PEGTL_STRING("*") {};
struct binary_div         : TAOCPP_PEGTL_STRING("/") {};
struct binary_mod         : TAOCPP_PEGTL_STRING("MOD") {};
struct binary_idiv        : TAOCPP_PEGTL_STRING("DIV") {};
struct binary_shift_left  : TAOCPP_PEGTL_STRING("<<") {};
struct binary_shift_right : TAOCPP_PEGTL_STRING(">>") {};
struct binary_lt          : TAOCPP_PEGTL_STRING("<") {};
struct binary_le          : TAOCPP_PEGTL_STRING("<=") {};
struct binary_gt          : TAOCPP_PEGTL_STRING(">") {};
struct binary_ge          : TAOCPP_PEGTL_STRING(">=") {};
struct binary_eq          : TAOCPP_PEGTL_STRING("==") {};
struct binary_ne          : TAOCPP_PEGTL_STRING("!=") {};
struct binary_bit_and     : TAOCPP_PEGTL_STRING("AND") {};
struct binary_bit_eor     : TAOCPP_PEGTL_STRING("EOR") {};
struct binary_bit_or      : TAOCPP_PEGTL_STRING("OR") {};
struct binary_bool_and    : TAOCPP_PEGTL_STRING("&&") {};
struct binary_bool_or     : TAOCPP_PEGTL_STRING("||") {};
struct binary_in          : TAOCPP_PEGTL_STRING("IN") {};
struct binary_assignment  : TAOCPP_PEGTL_STRING("=") {};
struct binary_bit_concat  : TAOCPP_PEGTL_STRING(":") {};

// Operator groups.
struct unary_operator           : pegtl::sor<unary_negate, unary_minus, unary_invert, unary_plus> {};
struct multiplicative_operator  : pegtl::sor<binary_mul, binary_div, binary_idiv, binary_mod> {};
struct additive_operator        : pegtl::sor<binary_plus, binary_minus> {};
struct shift_operator           : pegtl::sor<binary_shift_left, binary_shift_right> {};
struct relational_operator      : pegtl::sor<binary_le, binary_lt, binary_ge, binary_gt> {};
struct equality_operator        : pegtl::sor<binary_eq, binary_ne> {};
struct and_operator             : binary_bit_and {};
struct eor_operator             : binary_bit_eor {};
struct or_operator              : binary_bit_or {};
struct logical_and_operator     : binary_bool_and {};
struct logical_or_operator      : binary_bool_or {};
struct concatenation_operator   : binary_bit_concat {};
struct inclusion_operator       : binary_in {};
struct assignment_operator      : binary_assignment {};

// Keywords.
struct keyword_array       : TAOCPP_PEGTL_KEYWORD("array") {};
struct keyword_bit         : TAOCPP_PEGTL_KEYWORD("bit") {};
struct keyword_bitstring   : TAOCPP_PEGTL_KEYWORD("bitstring") {};
struct keyword_boolean     : TAOCPP_PEGTL_KEYWORD("boolean") {};
struct keyword_case        : TAOCPP_PEGTL_KEYWORD("case") {};
struct keyword_do          : TAOCPP_PEGTL_KEYWORD("do") {};
struct keyword_else        : TAOCPP_PEGTL_KEYWORD("else") {};
struct keyword_elsif       : TAOCPP_PEGTL_KEYWORD("elsif") {};
struct keyword_enumeration : TAOCPP_PEGTL_KEYWORD("enumeration") {};
struct keyword_for         : TAOCPP_PEGTL_KEYWORD("for") {};
struct keyword_if          : TAOCPP_PEGTL_KEYWORD("if") {};
struct keyword_integer     : TAOCPP_PEGTL_KEYWORD("integer") {};
struct keyword_list        : TAOCPP_PEGTL_KEYWORD("list") {};
struct keyword_of          : TAOCPP_PEGTL_KEYWORD("of") {};
struct keyword_otherwise   : TAOCPP_PEGTL_KEYWORD("otherwise") {};
struct keyword_real        : TAOCPP_PEGTL_KEYWORD("real") {};
struct keyword_repeat      : TAOCPP_PEGTL_KEYWORD("repeat") {};
struct keyword_return      : TAOCPP_PEGTL_KEYWORD("return") {};
struct keyword_then        : TAOCPP_PEGTL_KEYWORD("then") {};
struct keyword_to          : TAOCPP_PEGTL_KEYWORD("to") {};
struct keyword_until       : TAOCPP_PEGTL_KEYWORD("until") {};
struct keyword_when        : TAOCPP_PEGTL_KEYWORD("when") {};
struct keyword_while       : TAOCPP_PEGTL_KEYWORD("while") {};

struct keyword : pegtl::sor <
    keyword_array,
    keyword_bit,
    keyword_bitstring,
    keyword_boolean,
    keyword_case,
    keyword_do,
    keyword_else,
    keyword_elsif,
    keyword_enumeration,
    keyword_for,
    keyword_if,
    keyword_integer,
    keyword_list,
    keyword_of,
    keyword_otherwise,
    keyword_real,
    keyword_repeat,
    keyword_return,
    keyword_then,
    keyword_to,
    keyword_until,
    keyword_when,
    keyword_while
>
{
};

// Comments.
struct comment : pegtl::seq<pegtl::two<'/'>, pegtl::until<pegtl::eolf>> {};

// Ignore whitespaces and comments.
struct sep : pegtl::sor<pegtl::space, comment> {};
struct seps : pegtl::star<sep> {};
template <typename R>
struct pad : pegtl::pad<R, sep> {};

// Values.
struct value_ignored       : TAOCPP_PEGTL_STRING("-") {};
struct value_false         : TAOCPP_PEGTL_STRING("FALSE") {};
struct value_true          : TAOCPP_PEGTL_STRING("TRUE") {};
struct value_unknown       : TAOCPP_PEGTL_STRING("UNKNOWN") {};
struct value_undefined     : TAOCPP_PEGTL_STRING("UNDEFINED") {};
struct value_unpredictable : TAOCPP_PEGTL_STRING("UNPREDICTABLE") {};

// Boolean values.
struct boolean : pegtl::sor<value_false, value_true> {};

// Digits for the different integer bases.
struct base_two_digit        : pegtl::one<'0', '1'> {};
struct base_two_digit_masked : pegtl::one<'0', '1', 'x'> {};
struct base_eight_digit      : pegtl::range<'0', '7'> {};

// Integers for the different bases.
struct base_two_integer        : pegtl::seq<QUOTE, pegtl::plus<base_two_digit> , QUOTE> {};
struct base_two_integer_masked : pegtl::seq<QUOTE, pegtl::plus<base_two_digit_masked> , QUOTE> {};
struct base_eight_integer      : pegtl::seq<pegtl::one<'0'>, pegtl::star<base_eight_digit>> {};
struct base_sixteen_integer    : pegtl::seq<pegtl::one<'0'>, pegtl::one<'x', 'X'>, pegtl::plus<pegtl::xdigit>> {};
struct base_ten_integer        : pegtl::seq<pegtl::range<'1', '9'>, pegtl::star<pegtl::digit>> {};

// Generic integer.
struct number : pegtl::sor<base_two_integer, base_two_integer_masked, base_ten_integer, base_sixteen_integer, base_eight_integer> {};

// An identifier is a name that is not a keyword.
struct identifier : pegtl::seq<pegtl::not_at<keyword>, pegtl::identifier> {};

// Enumeration is either a list enclosed by curly brackets or a masked binary integer.
struct enumeration_atom    : pegtl::sor<identifier, number> {};
struct enumeration_list    : pegtl::list<enumeration_atom, COMMA, sep> {};
struct enumeration_element : pegtl::seq<LBRACE, enumeration_list, RBRACE> {};
struct enumeration         : pegtl::sor<base_two_integer_masked, enumeration_element> {};

// TODO: Missing these.
// struct array_access;
// struct procedure_call;
// list_atom = MatchFirst([ignored, procedure_call_expr, array_access_expr, boolean, identifier, number])

// List.
struct list_atom : pegtl::sor<value_ignored, boolean, identifier, number> {};
struct list_list : pegtl::list<list_atom, COMMA, sep> {};
struct list      : pegtl::seq<LPAR, list_list, RPAR> {};

// TODO: Is this the right thing to do?.
struct SEE                     : TAOCPP_PEGTL_STRING("SEE") {};
struct IMPLEMENTATION_DEFINED  : TAOCPP_PEGTL_STRING("IMPLEMENTATION_DEFINED") {};
struct SUBARCHITECTURE_DEFINED : TAOCPP_PEGTL_STRING("SUBARCHITECTURE_DEFINED") {};

struct expression;
struct parenthesized_expression : pegtl::seq<LPAR, expression, RPAR> {};
struct primary_expression       : pegtl::sor<parenthesized_expression, number, identifier> {};

struct assignment_expression;
struct argument_expression_list : pegtl::list<assignment_expression, COMMA, sep> {};

struct array_expression         : pegtl::seq<primary_expression, LBRACK, expression, RBRACK> {};
struct function_call_expression : pegtl::seq<primary_expression, LPAR, pegtl::opt<argument_expression_list>, RPAR> {};
struct field_access_expression  : pegtl::seq<primary_expression, DOT, identifier> {};

struct postfix_expression : pegtl::sor<
    array_expression,
    function_call_expression,
    field_access_expression,
    primary_expression
> {};

struct unary_expression : pegtl::sor<
    pegtl::seq<unary_operator, seps, unary_expression>,
    postfix_expression
> {};

template<typename Expression, typename Operator>
struct left_associative : pegtl::seq<
    Expression, seps, pegtl::star<pegtl::if_must<Operator, seps, Expression, seps>>
> {};

template<typename Expression, typename Operator>
struct right_associative : pegtl::seq<
    Expression, seps, pegtl::opt<pegtl::if_must<Operator, seps, right_associative<Expression, Operator>>>
> {};

struct concatenation_expression  : left_associative  < unary_expression          , concatenation_operator  > {};
struct multiplicative_expression : left_associative  < concatenation_expression  , multiplicative_operator > {};
struct additive_expression       : left_associative  < multiplicative_expression , additive_operator       > {};
struct shift_expression          : left_associative  < additive_expression       , shift_operator          > {};
struct inclusion_expression      : left_associative  < shift_expression          , inclusion_operator      > {};
struct relational_expression     : left_associative  < inclusion_expression      , relational_operator     > {};
struct equality_expression       : left_associative  < relational_expression     , equality_operator       > {};
struct and_expression            : left_associative  < equality_expression       , and_operator            > {};
struct eor_expression            : left_associative  < and_expression            , eor_operator            > {};
struct or_expression             : left_associative  < eor_expression            , or_operator             > {};
struct logical_and_expression    : left_associative  < or_expression             , logical_and_operator    > {};
struct logical_or_expression     : left_associative  < logical_and_expression    , logical_or_operator     > {};
struct assignment_expression     : right_associative < logical_or_expression     , assignment_operator     > {};

struct expression : pegtl::list<
    assignment_expression, COMMA, sep
> {};

struct grammar : pegtl::seq<
    expression, pegtl::eolf
> {};

// clang-format on

// Do nothing on generic types.
template <typename T>
struct TestAction {
    template <typename Input>
    static void apply(const Input& in, std::string& v)
    {
        // std::cout << "UNMATCHED -> " << typeid(T).name() << " -> " << in.string() << std::endl;
    }
};

template <typename GrammarRule, typename Iterator>
void test_parsing(Iterator&& tests)
{
    std::string value;
    for (auto test : tests) {
        pegtl::string_input<> in(test, __PRETTY_FUNCTION__);
        pegtl::parse<GrammarRule, TestAction>(in, value);
    }
}

#define ADD_TEST(TypeName, ...)                                                                          \
    static void test_##TypeName##_parsing()                                                              \
    {                                                                                                    \
        auto tests = { __VA_ARGS__ };                                                                    \
        test_parsing<TypeName>(tests);                                                                   \
    }                                                                                                    \
                                                                                                         \
    template <>                                                                                          \
    struct TestAction<TypeName> {                                                                        \
        template <typename Input>                                                                        \
        static void apply(const Input& in, std::string& v)                                               \
        {                                                                                                \
            std::cout << "TypeName ->" << typeid(TypeName).name() << " -> " << in.string() << std::endl; \
        }                                                                                                \
    };

#define DO_TEST(TypeName) test_##TypeName##_parsing()

struct ASTBuilderState {
};

template <typename T>
struct ASTBuilderActions {
    template <typename Input>
    static void apply(const Input& in, ASTBuilderState& state)
    {
        // std::cout << "UNMATCHED -> " << typeid(T).name() << " -> " << in.string() << std::endl;
    }
};

#define DEBUG_RULE_MATCH(rule)                                            \
    template <>                                                           \
    struct ASTBuilderActions<rule> {                                      \
        template <typename Input>                                         \
        static void apply(const Input& in, ASTBuilderState& state)        \
        {                                                                 \
            std::cout << #rule "::apply -> " << in.string() << std::endl; \
        }                                                                 \
    };

DEBUG_RULE_MATCH(number);
DEBUG_RULE_MATCH(identifier);

DEBUG_RULE_MATCH(unary_operator);
DEBUG_RULE_MATCH(multiplicative_operator);
DEBUG_RULE_MATCH(additive_operator);
DEBUG_RULE_MATCH(shift_operator);
DEBUG_RULE_MATCH(relational_operator);
DEBUG_RULE_MATCH(equality_operator);
DEBUG_RULE_MATCH(and_operator);
DEBUG_RULE_MATCH(eor_operator);
DEBUG_RULE_MATCH(or_operator);
DEBUG_RULE_MATCH(logical_and_operator);
DEBUG_RULE_MATCH(logical_or_operator);
DEBUG_RULE_MATCH(concatenation_operator);
DEBUG_RULE_MATCH(inclusion_operator);
DEBUG_RULE_MATCH(assignment_operator);

template <>
struct ASTBuilderActions<expression> {
    template <typename Input>
    static void apply(const Input& in, ASTBuilderState& state)
    {
        std::cout << "expression::apply -> " << in.string() << std::endl;
    }
};

// ADD_TEST(comment, "// AAAA", "// BBBB", "// CCCCDDDD");
// ADD_TEST(identifier, "while", "while_something");
// ADD_TEST(number, "\"0\"", "\"1\"", "\"x\"", "\"00\"", "\"01\"", "\"10\"", "\"11\"", "\"0x\"", "\"x0\"", "\"1x\"", "\"x1\"", "\"xx\"", "0", "1", "12", "123", "011", "0x10000");
// ADD_TEST(enumeration, "{0}", "{0, 1}", "{0, 1, 2}", "\"0000xxxx\"");
// ADD_TEST(list, "(0)", "(0, 1)", "(TRUE, FALSE, -, hola)");

ADD_TEST(
    grammar,
    "// This is a comment.",
    "example_identifier",
    "10101010",
    "-1",
    "+1",
    "!1",
    "~1",
    "-object",
    "+object",
    "!object",
    "~object",
    "pepe=papa",
    "pepe= papa",
    "pepe =papa",
    "pepe = papa + 1",
    "2222 = 3333, a = b",
    "2222 = 3333",
    "2222 = 3333 = 4444",
    "1 : hola",
    "1 IN hola",
    "1 * hola",
    "1 / hola",
    "1 MOD hola",
    "1 + hola",
    "1 - hola",
    "1 << hola",
    "1 >> hola",
    "1 < hola",
    "1 > hola",
    "1 <= hola",
    "1 >= hola",
    "1 == hola",
    "1 != hola",
    "1 AND hola",
    "1 OR hola",
    "1 EOR hola",
    "1 && hola",
    "1 || hola",
    "2 + 3 * 4 * 5 - 6",
    "my_array[0]",
    "my_array[hola]",
    "my_array[1+1]",
    "my_array[1+hola]",
    "my_array()",
    "my_array(1, 2)",
    "my_array(1, 2, 3)",
    "my_array(hola, hola)",
    "my_array(1, hola)",
    "my_array(hola, 1)",
    "object.field",
    "-object.field",
    "+object.field",
    "!object.field",
    "~object.field");

int main(int argc, char** argv)
{
    const size_t issues_found = pegtl::analyze<grammar>();
    if (issues_found) {
        std::cout << "There are " << issues_found << " errors in the grammar." << std::endl;
        return -1;
    }

    // DO_TEST(comment);
    // DO_TEST(identifier);
    // DO_TEST(number);
    // DO_TEST(enumeration);
    // DO_TEST(list);
    // DO_TEST(grammar);

    ASTBuilderState state;
    pegtl::argv_input<> in(argv, 1);
    pegtl::parse<grammar, ASTBuilderActions>(in, state);
    return 0;
}
