import re
import pytest

from klp import EStr


def test__init():
    s = EStr("This is a test")
    assert s == "This is a test"


def test__init_empty():
    s = EStr("")
    assert s == ""


def test__basic_ops():
    s = EStr("This is a test")
    assert str(s) == "This is a test"
    assert len(s) == 14
    assert s[0] == "T"
    assert s[1] == "h"
    assert s[2] == "i"


def test__col():
    s = EStr("This is a test")
    assert s.col(0) == "This"
    assert s.col(1) == "is"
    assert s.col(2) == "a"
    assert s.col(3) == "test"
    assert s.col(4) is None


def test__cols_basic():
    s = EStr("This is  a test  with 7 columns")
    assert s.cols() == ["This", "is", "a", "test", "with", "7", "columns"]
    assert s.cols(0, 3) == ["This", "test"]
    assert s.cols(0, -1, 2, 2) == ["This", "columns", "a", "a"]
    assert s.cols("0,3") == "This test"
    assert s.cols("1") == "is"
    assert s.cols(1) == "is"
    assert s.cols("14") == ""
    assert s.cols("1:3") == "is a"
    assert s.cols("-2,2,4:") == "7 a with 7 columns"


def test__cols_with_separators():
    s = EStr("This|is a|test with|4 columns")
    assert s.cols("1:3", sep="|") == "is a test with"
    assert s.cols("-2,2,4:", sep="|", outsep=":") == "test with:test with"


def test__cols_empty_sep():
    # Character-by-character splitting with empty separators
    text = EStr("Hello")
    assert text.cols("0,2,4", sep="", outsep="") == "Hlo"  # Single arg joins indices
    assert text.cols("1:4", sep="", outsep="") == "ell"  # Single slice
    assert text.cols("0,2", "4", sep="", outsep="") == [
        "Hl",
        "o",
    ]  # Multiple args as list
    assert text.cols(0, "2:4", sep="", outsep="") == [
        "H",
        "ll",
    ]  # Mix of single index and slice

    assert text.cols(0, "2:4", sep="", outsep="!") == [
        "H",
        "l!l",
    ]  # Non-empty outsep

    assert text.cols(0, "2:4", "1:4", sep="", outsep=".") == [
        "H",
        "l.l",
        "e.l.l",
    ]  # Overlapping columns

    # Character-by-character splitting for DNA sequence
    dna = EStr("ATCGTA")
    assert dna.cols(sep="") == ["A", "T", "C", "G", "T", "A"]
    assert dna.cols("1,3,5", sep="") == "T G A"
    assert dna.cols("0:3", sep="", outsep="") == "ATC"

    # Multiple arguments with character splitting
    text = EStr("Hello world!")
    assert text.cols("0", "1:5", sep="") == ["H", "e l l o"]
    assert text.cols("0:4", "6:9", sep="", outsep="-") == ["H-e-l-l", "w-o-r"]

    # Unicode characters
    emoji = EStr("👋🌍")
    assert emoji.cols(sep="") == ["👋", "🌍"]
    assert emoji.cols("0", sep="") == "👋"


def test__cols_with_regex():
    s = EStr("This2334is7453a654test232with232regex")
    assert s.cols("1:5", sep=re.compile(r"\d+")) == "is a test with"


def test_before_basic():
    """Test basic functionality of before()"""
    s = EStr("name:alice")
    assert s.before(":") == "name"
    assert isinstance(s.before(":"), EStr)  # Return type should be EStr


def test_before_not_found():
    """Test when substring is not found"""
    s = EStr("test")
    assert s.before("@") == ""
    assert isinstance(s.before("@"), EStr)


def test_before_empty_inputs():
    """Test with empty strings"""
    s = EStr("")
    assert s.before("") == ""  # Empty source string
    assert s.before("x") == ""  # Empty source string, non-empty target

    s = EStr("hello")
    assert s.before("") == "hello"  # Empty target string returns full string


def test_before_none_input():
    """Test handling of None input"""
    s = EStr("test")
    with pytest.raises(TypeError, match="Input cannot be None"):
        s.before(None)


def test_before_multiple_occurrences():
    """Test when substring appears multiple times"""
    s = EStr("name:alice:bob")
    assert s.before(":") == "name"  # Should return everything before first occurrence


def test_before_target_at_start():
    """Test when target is at the start of string"""
    s = EStr(":name")
    assert s.before(":") == ""


def test_before_target_equals_source():
    """Test when target equals entire source"""
    s = EStr("test")
    assert s.before("test") == ""


def test_before_target_longer():
    """Test when target is longer than source"""
    s = EStr("abc")
    assert s.before("abcd") == ""


def test_after_basic():
    """Test basic functionality of after()"""
    s = EStr("name:alice")
    assert s.after(":") == "alice"
    assert isinstance(s.after(":"), EStr)  # Return type should be EStr


def test_after_not_found():
    """Test when substring is not found"""
    s = EStr("test")
    assert s.after("@") == ""
    assert isinstance(s.after("@"), EStr)


def test_after_empty_inputs():
    """Test with empty strings"""
    s = EStr("")
    assert s.after("") == ""  # Empty source string
    assert s.after("x") == ""  # Empty source string, non-empty target

    s = EStr("hello")
    assert s.after("") == "hello"  # Empty target string returns full string


def test_after_none_input():
    """Test handling of None input"""
    s = EStr("test")
    with pytest.raises(TypeError, match="Input cannot be None"):
        s.after(None)


def test_after_multiple_occurrences():
    """Test when substring appears multiple times"""
    s = EStr("name:alice:bob")
    assert (
        s.after(":") == "alice:bob"
    )  # Should return everything after first occurrence


def test_after_target_at_end():
    """Test when target is at the end of string"""
    s = EStr("name:")
    assert s.after(":") == ""


def test_after_target_equals_source():
    """Test when target equals entire source"""
    s = EStr("test")
    assert s.after("test") == ""


def test_after_target_longer():
    """Test when target is longer than source"""
    s = EStr("abc")
    assert s.after("abcd") == ""


def test_after_multichar():
    """Test after() with multi-character targets"""
    s = EStr("prefix-->content")
    assert s.after("-->") == "content"

    s = EStr("multiple==twice==here")
    assert s.after("==") == "twice==here"  # Matches first occurrence

    s = EStr("longprefix_______text")
    assert s.after("_______") == "text"


def test_before_multichar():
    """Test before() with multi-character targets"""
    s = EStr("content<--suffix")
    assert s.before("<--") == "content"

    s = EStr("here==twice==multiple")
    assert s.before("==") == "here"  # Matches first occurrence

    s = EStr("text_______longsuffix")
    assert s.before("_______") == "text"


def test_between_multichar():
    """Test between() with multi-character targets"""
    s = EStr("pre<!--content-->post")
    assert s.between("<!--", "-->") == "content"

    s = EStr("start==middle==end==other")
    assert s.between("==", "==") == "middle"

    s = EStr("begin#####middle@@@@@end")
    assert s.between("#####", "@@@@@") == "middle"

    # Different length delimiters
    s = EStr("prefix-->content<----suffix")
    assert s.between("-->", "<----") == "content"


def test_between_basic():
    """Test basic functionality of between()"""
    s = EStr("name:alice:bob")
    assert s.between(":", ":") == "alice"
    assert isinstance(s.between(":", ":"), EStr)  # Return type should be EStr


def test_between_html_tags():
    """Test extracting content between HTML-like tags"""
    s = EStr("<tag>value</tag>")
    assert s.between(">", "<") == "value"


def test_between_not_found():
    """Test when substrings are not found"""
    s = EStr("test")
    assert s.between("[", "]") == ""
    assert s.between("test", "]") == ""
    assert s.between("[", "test") == ""


def test_between_empty_inputs():
    """Test with empty strings"""
    s = EStr("")
    assert s.between("", "") == ""  # Empty source string
    assert s.between("x", "y") == ""  # Empty source string, non-empty targets

    s = EStr("hello")
    assert s.between("", "") == "hello"  # Empty targets return full string


def test_between_none_inputs():
    """Test handling of None inputs"""
    s = EStr("test")
    with pytest.raises(TypeError, match="Input cannot be None"):
        s.between(None, "")
    with pytest.raises(TypeError, match="Input cannot be None"):
        s.between("", None)
    with pytest.raises(TypeError, match="Input cannot be None"):
        s.between(None, None)


def test_between_multiple_occurrences():
    """Test when substrings appear multiple times"""
    s = EStr("[first][second][third]")
    assert s.between("[", "]") == "first"


def test_between_nested():
    """Test with nested delimiters"""
    # Just matches from first opening delimiter to next closing one - no bracket matching
    s = EStr("outer[inner[deep]inner]outer")
    assert s.between("[", "]") == "inner[deep"


def test_between_a_after_b():
    """Test when first substring appears after second"""
    s = EStr("]before[")
    assert s.between("[", "]") == ""


def test_between_adjacent():
    """Test when substrings are adjacent"""
    s = EStr("name[]value")
    assert s.between("[", "]") == ""


def test_before_doctest_examples():
    """Test the examples provided in the docstring"""
    assert EStr("name:alice").before(":") == "name"
    assert EStr("test").before("@") == ""
    assert EStr("a:b:c").before(":") == "a"


def test_before_edge_cases():
    """Test edge cases for before() method"""
    assert EStr("").before("x") == ""  # Empty source string
    assert EStr("test").before("") == "test"  # Empty target string
    assert EStr("test").before("test123") == ""  # Target longer than source


def test_after_doctest_examples():
    """Test the examples provided in the docstring"""
    assert EStr("name:alice").after(":") == "alice"
    assert EStr("test").after("@") == ""
    assert EStr("a:b:c").after(":") == "b:c"


def test_after_edge_cases():
    """Test edge cases for after() method"""
    assert EStr("").after("x") == ""  # Empty source string
    assert EStr("test").after("") == "test"  # Empty target string
    assert EStr("test").after("test123") == ""  # Target longer than source


def test_between_doctest_examples():
    """Test the examples provided in the docstring"""
    assert EStr("name:alice:bob").between(":", ":") == "alice"
    assert EStr("<tag>value</tag>").between(">", "<") == "value"
    assert EStr("no delimiters").between("[", "]") == ""


def test_between_edge_cases():
    """Test edge cases for between() method"""
    assert EStr("").between("x", "y") == ""  # Empty source string
    assert EStr("test").between("", "") == "test"  # Empty delimiters
    assert (
        EStr("test").between("test123", "x") == ""
    )  # First delimiter longer than source


def test_between_complex_cases():
    """Test more complex scenarios for between() method"""
    assert EStr("[[nested]]").between("[", "]") == "[nested"  # Nested delimiters
    assert EStr("start:middle:end").between(":", ":") == "middle"  # Multiple delimiters
    assert (
        EStr("no second delimiter").between("no ", "x") == ""
    )  # Missing second delimiter
    assert EStr("text:").between(":", ":") == ""  # No content between delimiters


def test_starting_with_doctest_examples():
    """Test the examples provided in the docstring"""
    assert EStr("hello world").starting_with("o w") == "o world"
    assert EStr("hello world").starting_with("hello") == "hello world"
    assert EStr("test").starting_with("x") == ""
    assert EStr("abc").starting_with("abcd") == ""


def test_starting_with_edge_cases():
    """Test edge cases for starting_with() method"""
    assert EStr("").starting_with("x") == ""  # Empty source string
    assert EStr("test").starting_with("") == "test"  # Empty target string
    assert EStr("test").starting_with("test123") == ""  # Target longer than source


def test_starting_with_multiple_occurrences():
    """Test behavior with multiple occurrences of target"""
    assert EStr("hello hello world").starting_with("hello") == "hello hello world"
    assert EStr("start start end").starting_with("start") == "start start end"
    assert EStr("prefixprefixsuffix").starting_with("prefix") == "prefixprefixsuffix"


def test_ending_with_doctest_examples():
    """Test the examples provided in the docstring"""
    assert EStr("hello world").ending_with("world") == "hello world"
    assert EStr("hello world").ending_with("o wo") == "hello wo"
    assert EStr("test").ending_with("x") == ""
    assert EStr("abc").ending_with("abcd") == ""


def test_ending_with_edge_cases():
    """Test edge cases for ending_with() method"""
    assert EStr("").ending_with("x") == ""  # Empty source string
    assert EStr("test").ending_with("") == "test"  # Empty target string
    assert EStr("test").ending_with("test123") == ""  # Target longer than source


def test_ending_with_multiple_occurrences():
    """Test behavior with multiple occurrences of target"""
    assert EStr("world hello world").ending_with("world") == "world"
    assert EStr("end start end").ending_with("end") == "end"
    assert EStr("prefixsuffixsuffix").ending_with("suffix") == "prefixsuffix"


def test_chaining_methods():
    """Test that methods can be chained together"""
    text = EStr("start:middle:end")
    assert text.after(":").before(":") == "middle"
    assert text.between(":", ":").starting_with("mid") == "middle"
    assert text.starting_with("start").ending_with("middle:end") == "start:middle:end"


def test_before_nth_match():
    """Test nth match functionality of before()"""
    s = EStr("a:b:c:d")
    assert s.before(":", n=1) == "a"  # First match (default)
    assert s.before(":", n=2) == "a:b"  # Second match
    assert s.before(":", n=3) == "a:b:c"  # Third match
    assert s.before(":", n=0) == ""  # Invalid n
    assert s.before(":", n=-1) == "a:b:c"  # Last match
    assert s.before(":", n=-2) == "a:b"  # Second to last match
    assert s.before(":", n=-3) == "a"  # Third to last match
    assert s.before(":", n=99) == ""  # n beyond available matches
    assert s.before(":", n=-99) == ""  # negative n beyond available matches


def test_after_nth_match():
    """Test nth match functionality of after()"""
    s = EStr("a:b:c:d")
    assert s.after(":", n=1) == "b:c:d"  # First match (default)
    assert s.after(":", n=2) == "c:d"  # Second match
    assert s.after(":", n=3) == "d"  # Third match
    assert s.after(":", n=0) == ""  # Invalid n
    assert s.after(":", n=-1) == "d"  # Last match
    assert s.after(":", n=-2) == "c:d"  # Second to last match
    assert s.after(":", n=-3) == "b:c:d"  # Third to last match
    assert s.after(":", n=99) == ""  # n beyond available matches
    assert s.after(":", n=-99) == ""  # negative n beyond available matches


def test_between_nth_match():
    """Test nth match functionality of between()"""
    s = EStr("[1][2][3][4]")
    assert s.between("[", "]", n=1) == "1"  # First match (default)
    assert s.between("[", "]", n=2) == "2"  # Second match
    assert s.between("[", "]", n=3) == "3"  # Third match
    assert s.between("[", "]", n=0) == ""  # Invalid n
    assert s.between("[", "]", n=-1) == "4"  # Last match
    assert s.between("[", "]", n=-2) == "3"  # Second to last match
    assert s.between("[", "]", n=-3) == "2"  # Third to last match
    assert s.between("[", "]", n=99) == ""  # n beyond available matches
    assert s.between("[", "]", n=-99) == ""  # negative n beyond available matches

    # Test when second delimiter has multiple matches after nth first delimiter
    s = EStr("a[1]b[2]c[3]d")
    assert (
        s.between("[", "]", n=2) == "2"
    )  # Should match with closest closing delimiter


def test_starting_with_nth_match():
    """Test nth match functionality of starting_with()"""
    s = EStr("start middle start end start")
    assert (
        s.starting_with("start", n=1) == "start middle start end start"
    )  # First match (default)
    assert s.starting_with("start", n=2) == "start end start"  # Second match
    assert s.starting_with("start", n=3) == "start"  # Third match
    assert s.starting_with("start", n=0) == ""  # Invalid n
    assert s.starting_with("start", n=-1) == "start"  # Last match
    assert s.starting_with("start", n=-2) == "start end start"  # Second to last match
    assert (
        s.starting_with("start", n=-3) == "start middle start end start"
    )  # Third to last match
    assert s.starting_with("start", n=99) == ""  # n beyond available matches
    assert s.starting_with("start", n=-99) == ""  # negative n beyond available matches


def test_ending_with_nth_match():
    """Test nth match functionality of ending_with()"""
    s = EStr("start middle start end start")
    assert s.ending_with("start", n=1) == "start"  # First match from left (default)
    assert s.ending_with("start", n=2) == "start middle start"  # Second match from left
    assert (
        s.ending_with("start", n=3) == "start middle start end start"
    )  # Third match from left
    assert s.ending_with("start", n=0) == ""  # Invalid n
    assert (
        s.ending_with("start", n=-1) == "start middle start end start"
    )  # Last match from right
    assert (
        s.ending_with("start", n=-2) == "start middle start"
    )  # Second to last match from right
    assert s.ending_with("start", n=-3) == "start"  # Third to last match from right
    assert s.ending_with("start", n=99) == ""  # n beyond available matches
    assert s.ending_with("start", n=-99) == ""  # negative n beyond available matches


def test_nth_match_with_overlapping():
    """Test nth match behavior with overlapping matches"""
    s = EStr("aaaaa")
    assert s.before("aa", n=1) == ""  # First 'aa'
    assert s.before("aa", n=2) == "a"  # Second 'aa'
    assert s.before("aa", n=3) == "aa"  # Third 'aa'
    assert s.before("aa", n=4) == "aaa"  # Fourth 'aa'

    assert s.after("aa", n=1) == "aaa"  # First 'aa'
    assert s.after("aa", n=2) == "aa"  # Second 'aa'
    assert s.after("aa", n=3) == "a"  # Third 'aa'
    assert s.after("aa", n=4) == ""  # Fourth 'aa'


def test_nth_match_complex_patterns():
    """Test nth match with more complex patterns"""
    # Test with multi-character patterns
    s = EStr("abc--def--ghi--jkl")
    assert s.before("--", n=2) == "abc--def"
    assert s.after("--", n=2) == "ghi--jkl"

    # Test with empty strings between matches
    s = EStr("::text::")
    assert s.between(":", ":", n=1) == ""  # First pair
    assert s.between(":", ":", n=2) == "text"  # Second pair

    # Test with mixed delimiters
    s = EStr("[1]{2}[3]{4}")
    assert s.between("[", "]", n=1) == "1"
    assert s.between("[", "]", n=2) == "3"
    assert s.between("{", "}", n=1) == "2"
    assert s.between("{", "}", n=2) == "4"


def test_nth_match_whitespace():
    """Test nth match behavior with whitespace patterns"""
    s = EStr("  word  another  word  ")
    assert s.between("  ", "  ", n=1) == "word"
    assert s.between("  ", "  ", n=2) == "another"
    assert s.between("  ", "  ", n=3) == "word"


def test_nth_match_empty_and_edge():
    """Test nth match edge cases"""
    # Empty string
    s = EStr("")
    assert s.before("x", n=1) == ""
    assert s.before("x", n=2) == ""

    # Empty pattern
    s = EStr("text")
    assert s.before("", n=1) == "text"
    assert s.before("", n=2) == "text"

    # Pattern longer than string
    s = EStr("abc")
    assert s.before("abcd", n=1) == ""
    assert s.before("abcd", n=2) == ""
