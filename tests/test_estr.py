import re
import pytest

from klp import EStr


def test_estr_init():
    s = EStr("This is a test")
    assert s == "This is a test"


def test_estr_init_empty():
    s = EStr("")
    assert s == ""


def test_estr_basic_ops():
    s = EStr("This is a test")
    assert str(s) == "This is a test"
    assert len(s) == 14
    assert s[0] == "T"
    assert s[1] == "h"
    assert s[2] == "i"


def test_estr_col():
    s = EStr("This is a test")
    assert s.col(0) == "This"
    assert s.col(1) == "is"
    assert s.col(2) == "a"
    assert s.col(3) == "test"
    assert s.col(4) is None


def test_estr_cols_basic():
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


def test_estr_cols_with_separators():
    s = EStr("This|is a|test with|4 columns")
    assert s.cols("1:3", sep="|") == "is a test with"
    assert s.cols("-2,2,4:", sep="|", outsep=":") == "test with:test with"


def test_estr_cols_empty_sep():
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


def test_estr_cols_with_regex():
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
