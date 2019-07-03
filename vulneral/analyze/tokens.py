
class Tokens:
	# tokens to ignore while scanning
	$T_IGNORE = [
		T_BAD_CHARACTER,
		T_DOC_COMMENT,
		T_COMMENT,
		#T_ML_COMMENT,
		T_INLINE_HTML,
		T_WHITESPACE,
		T_OPEN_TAG
		#T_CLOSE_TAG
	]
	
	# code blocks that should be ignored as requirement
	$T_LOOP_CONTROL = [
		#T_DO, # removed, because DO..WHILE is rewritten to WHILE
		T_WHILE,
		T_FOR,
		T_FOREACH
	]
	
	# control structures
	$T_FLOW_CONTROL = [
		T_IF, 
		T_SWITCH, 
		T_CASE, 
		T_ELSE, 
		T_ELSEIF
	]	
	
	# variable assignment tokens
	$T_ASSIGNMENT = [
		T_AND_EQUAL,
		T_CONCAT_EQUAL,
		T_DIV_EQUAL,
		T_MINUS_EQUAL,
		T_MOD_EQUAL,
		T_MUL_EQUAL,
		T_OR_EQUAL,
		T_PLUS_EQUAL,
		T_SL_EQUAL,
		T_SR_EQUAL,
		T_XOR_EQUAL
	]
	
	# variable assignment tokens that prevent tainting
	$T_ASSIGNMENT_SECURE = [
		T_DIV_EQUAL,
		T_MINUS_EQUAL,
		T_MOD_EQUAL,
		T_MUL_EQUAL,
		T_OR_EQUAL,
		T_PLUS_EQUAL,
		T_SL_EQUAL,
		T_SR_EQUAL,
		T_XOR_EQUAL
	]
	
	# condition operators
	$T_OPERATOR = [
		T_IS_EQUAL,
		T_IS_GREATER_OR_EQUAL,
		T_IS_IDENTICAL,
		T_IS_NOT_EQUAL,
		T_IS_NOT_IDENTICAL,
		T_IS_SMALLER_OR_EQUAL
	]
	
	# all function call tokens
	$T_FUNCTIONS = [
		T_STRING, # all functions
		T_EVAL,
		T_INCLUDE,
		T_INCLUDE_ONCE,
		T_REQUIRE,
		T_REQUIRE_ONCE
	]
	
	# including operation tokens
	$T_INCLUDES = [
		T_INCLUDE,
		T_INCLUDE_ONCE,
		T_REQUIRE,
		T_REQUIRE_ONCE
	]
	
	# XSS affected operation tokens
	$T_XSS = [
		T_PRINT,
		T_ECHO,
		T_OPEN_TAG_WITH_ECHO,
		T_EXIT
	]
	
	# securing operation tokens
	$T_CASTS = [
		T_BOOL_CAST,
		T_DOUBLE_CAST,
		T_INT_CAST,
		T_UNSET_CAST,
		T_UNSET
	]
	
	# tokens that will have a space before and after in the output, besides $T_OPERATOR and $T_ASSIGNMENT
	$T_SPACE_WRAP = [
		T_AS,
		T_BOOLEAN_AND,
		T_BOOLEAN_OR,
		T_LOGICAL_AND,
		T_LOGICAL_OR,
		T_LOGICAL_XOR,
		T_SL,
		T_SR,
		T_CASE,
		T_ELSE,
		T_GLOBAL,
		T_NEW
	]
	
	# arithmetical operators to detect automatic typecasts
	$T_ARITHMETIC = [
		T_INC,
		T_DEC
	]
	
	# arithmetical operators to detect automatic typecasts
	$S_ARITHMETIC = [
		'+',
		'-',
		'*',
		'/',
		'%'
	]
	
	# strings that will have a space before and after in the output besides $S_ARITHMETIC
	$S_SPACE_WRAP = [
		'.',
		'=',
		'>',
		'<',
		':',
		'?'
	]
	
# define own token for include ending
T_INCLUDE_END = 380