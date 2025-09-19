/* immediates */
alert(0); // 0
alert(1); // 1
alert(10); // 10
alert(127); // 127
alert(32767); // 32767
alert(2147483647); // 2147483647
alert(9223372036854775807); // 9223372036854775807
alert(0x10); // 16
alert(0x7fff); // 32767
alert(0x7FFF); // 32767
alert(0x7fffffff); // 2147483647
alert(0x7fffffffffffffff); // 9223372036854775807
alert(010); // 8
alert(077777); // 32767
alert(017777777777); // 2147483647
alert(0777777777777777777777); // 9223372036854775807
alert(0b10); // 2
alert(0b111111111111111); // 32767
alert(0b1111111111111111111111111111111); // 2147483647
alert(0b111111111111111111111111111111111111111111111111111111111111111); // 9223372036854775807

/* variables */
var QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ;
alert(QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ); // 0
var b = 2;
alert(b); // 2
var c, d = 3;
alert(c); // 0
alert(d); // 3

/* comma operator */
alert((0, 1)); // 1
alert((1, 0)); // 0
var c = 4, d = 5;
alert((c, d)); // 5
alert((d, c)); // 4

/* assignments */
var e, f = 6;
alert(e); // 0
alert(f); // 6
e = 7;
alert(e); // 7
alert(f); // 6
f = 8;
alert(e); // 7
alert(f); // 8
e = f = 9;
alert(e); // 9
alert(f); // 9
var g = 10, h = 11;
alert(g); // 10
alert(h); // 11
g += 2;
alert(g); // 12
alert(h); // 11
h += g;
alert(g); // 12
alert(h); // 23
h -= g;
alert(g); // 12
alert(h); // 11
g += h += 2;
alert(g); // 25
alert(h); // 13

/* conditional operator */
alert(0 ? 12 : 13); // 13
alert(14 ? 15 : 16); // 15
var i, j = 17, k = 18;
alert(i ? j : k); // 18
i = 19;
alert(i ? j : k); // 17

/* or */
alert(0 || 0); // 0
alert(0 || 20); // 20
alert(21 || 0); // 21
alert(22 || 23); // 22

/* and */
alert(0 && 0); // 0
alert(0 && 24); // 0
alert(25 && 0); // 0
alert(26 && 27); // 27

/* bor */
alert(0 | 0); // 0
alert(0 | 28); // 28
alert(29 | 0); // 29
alert(30 | 32); // 62

/* band */
alert(0 & 0); // 0
alert(0 & 33); // 0
alert(34 & 0); // 0
alert(35 & 36); // 32

/* bxor */
alert(0 ^ 0); // 0
alert(0 ^ 37); // 37
alert(38 ^ 0); // 38
alert(39 ^ 40); // 15

/* equality */
alert(0 == 0); // 1
alert(0 != 0); // 0
alert(0 == 41); // 0
alert(0 != 42); // 1
alert(43 == 0); // 0
alert(44 != 0); // 1
alert(45 == 46); // 0
alert(45 == 46); // 0
alert(47 != 48); // 1

/* comparison */
alert(0 < 0); // 0
alert(0 <= 0); // 1
alert(0 > 0); // 0
alert(0 >= 0); // 1
alert(0 < 49); // 1
alert(0 <= 50); // 1
alert(0 > 51); // 0
alert(0 >= 52); // 0
alert(53 < 0); // 0
alert(54 <= 0); // 0
alert(55 > 0); // 1
alert(56 >= 0); // 1
alert(57 < 58); // 1
alert(59 <= 60); // 1
alert(61 > 62); // 0
alert(63 >= 64); // 0
alert(65 < 65); // 0
alert(66 <= 66); // 1
alert(67 > 67); // 0
alert(68 >= 68); // 1

/* shift */
alert(0 << 0); // 0
alert(0 << 1); // 0
alert(0 << 2); // 0
alert(0 << 63); // 0
alert(1 << 0); // 1
alert(1 << 1); // 2
alert(1 << 2); // 4
alert(1 << 62); // 4611686018427387904
alert(2 << 0); // 2
alert(2 << 1); // 4
alert(2 << 2); // 8
alert(2 << 61); // 4611686018427387904
alert(0 >> 0); // 0
alert(0 >> 1); // 0
alert(0 >> 2); // 0
alert(0 >> 63); // 0
alert(1 >> 0); // 1
alert(1 >> 1); // 0
alert(1 >> 2); // 0
alert(1 >> 62); // 0
alert(2 >> 0); // 2
alert(2 >> 1); // 1
alert(2 >> 2); // 0
alert(2 >> 61); // 0

/* additive */
alert(0 + 0); // 0
alert(0 + 69); // 69
alert(70 + 0); // 70
alert(71 + 72); // 143
alert(73 + 74 + 75); // 222
alert(76 - 77); // -1
alert(78 - 79 - 80); // -81

/* multiplicative */
alert(0 * 0); // 0
alert(0 * 81); // 0
alert(82 * 0); // 0
alert(83 * 84); // 6972
alert(83 * 84 * 85); // 592620
alert(0 / 1); // 0
alert(1 / 1); // 1
alert(86 / 1); // 86
alert(0 / 87); // 0
alert(1 / 88); // 0
alert(89 / 90); // 0
alert(91 / 91); // 1
alert(93 / 92); // 1
alert(0 % 1); // 0
alert(1 % 1); // 0
alert(93 % 1); // 0
alert(0 % 94); // 0
alert(1 % 95); // 1
alert(96 % 97); // 96
alert(98 % 98); // 0
alert(100 % 99); // 1

/* unary */
alert(+101); // 101
alert(-102); // -102
alert(+(+103)); // 103
alert(+(-104)); // -104
alert(-(+105)); // -105
alert(-(-106)); // 106
alert(~0); // -1
alert(~1); // -2
alert(~107); // -108
alert(!0); // 1
alert(!1); // 0
alert(!108); // 0
alert(~-1); // 0
alert(-~1); // 2

/* increment/decrement */
var w = 172;
alert(w++); // 172
alert(w++); // 173
alert(w++); // 174
alert(++w); // 176
alert(++w); // 177
alert(++w); // 178
alert(w--); // 178
alert(w--); // 177
alert(w--); // 176
alert(--w); // 174
alert(--w); // 173
alert(--w); // 172

/* arguments */
function func1() {
	alert(arguments.length); // 0
}
func1();
function func2(l) {
	alert(arguments.length); // 1
	alert(arguments[0]); // 109
	alert(l); // 109
}
func2(109);
function func3(m, n) {
	alert(arguments.length); // 2
	alert(arguments[0]); // 110
	alert(arguments[1]); // 111
	alert(m); // 110
	alert(n); // 111
}
func3(110, 111);
function func3(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10) {
	alert(arguments.length); // 10
	alert(arguments[0]); // 112
	alert(arguments[1]); // 113
	alert(arguments[2]); // 114
	alert(arguments[3]); // 115
	alert(arguments[4]); // 116
	alert(arguments[5]); // 117
	alert(arguments[6]); // 118
	alert(arguments[7]); // 119
	alert(arguments[8]); // 120
	alert(arguments[9]); // 121
	alert(arg1); // 112
	alert(arg2); // 113
	alert(arg3); // 114
	alert(arg4); // 115
	alert(arg5); // 116
	alert(arg6); // 117
	alert(arg7); // 118
	alert(arg8); // 119
	alert(arg9); // 120
	alert(arg10); // 121
}
func3(112, 113, 114, 115, 116, 117, 118, 119, 120, 121);

/* operator precedence */
var o;
alert((122,o=123)); // 123
alert(o); // 123
var p;
alert(p=124?125:126); // 125
alert(127?128||129:130); // 128
alert(131?132:133||134); // 132
alert(135||136&&137); // 135
alert((135||136)&&137); // 137
alert(139&140==140); // 1
alert((139&140)==140); // 0
alert(141==142<143); // 0
alert((141==142)<143); // 1
alert(144<145<<1); // 1
alert((144<145)<<1); // 2
alert(146<<1+2); // 1168
alert((146<<1)+2); // 294
alert(147+148*149); // 22199
alert((147+148)*149); // 43955
alert(~150+151); // 0
alert(~(150+151)); // -302

/* scope */
var q = 152;
var r = 153;
alert(q); // 152
alert(r); // 153
{
	var q = 154;
	r = 155;
	alert(q); // 154
	alert(r); // 155
}
alert(q); // 152
alert(r); // 155

/* debugger statement - use when running in gb */
/* debugger; */

/* do...while */
var s = 159;
do {
	alert(s);
	s -= 1;
} while (s >= 156);
// 159
// 158
// 157
// 156

/* for */
for (var t = 160; t < 163; t += 1) {
	alert(t);
}
// 160
// 161
// 162
var u;
for (u = 164; u < 167; u += 1) {
	alert(u);
}
// 164
// 165
// 166
function func4() {
	var v = 168;
	for (;;) {
		alert(v);
		v += 1;
		if (v == 171) return;
	}
}
func4();
// 168
// 169
// 170

/* function */
var x = 173;
alert(x); // 173
function func5() {
	alert(x); // 173
	x = 174;
	alert(x); // 174
}
func5();
alert(x); // 174
var y = 175;
alert(y); // 175
function func6(y) {
	alert(y); // 175
	y = 176;
	alert(y); // 176
}
func6(y);
alert(y); // 175

var z = 204;
var aa = 205;
var ab = 206;
function func10() {
	alert(z);
	alert(aa);
	alert(ab);
	var z = 207;
	var aa = 208;
	ab = 209;
	alert(z);
	alert(aa);
	alert(ab);
	function func11() {
		alert(z);
		alert(aa);
		alert(ab);
		var z = 210;
		aa = 211;
		ab = 212;
		alert(z);
		alert(aa);
		alert(ab);
	}
	alert(z);
	alert(aa);
	alert(ab);
	func11();
	alert(z);
	alert(aa);
	alert(ab);
}
alert(z); // 204
alert(aa); // 205
alert(ab); // 206
func10();
// 204
// 205
// 206
// 207
// 208
// 209
// 207
// 208
// 209
// 207
// 208
// 209
// 210
// 211
// 212
// 207
// 211
// 212
alert(z); // 204
alert(aa); // 211
alert(ab); // 212

/* if */
if (0) alert(177);
if (1) alert(178); // 178
var x = 179;
if (x) alert(180); // 180
if (!x) alert(181);
var y = 0;
if (y) alert(182);
if (!y) alert(183); // 183
if (0) alert(184); else alert(185); // 185
if (1) alert(186); else alert(187); // 186
if (x) alert(188); else alert(189); // 188
if (!x) alert(190); else alert(191); // 191
if (y) alert(192); else alert(193); // 193
if (!y) alert(194); else alert(195); // 194

/* return */
function func7() {
}
alert(func7()); // 0
function func8() {
	return 0;
	alert(195);
}
alert(func8()); // 0
function func9() {
	return 196;
	alert(197);
}
alert(func9()); // 196

/* semicolon */
;;;;;
alert(198); // 198

/* while */
var s = 203;
do {
	alert(s);
	s--;
} while (s > 199);
// 203
// 202
// 201
// 200
