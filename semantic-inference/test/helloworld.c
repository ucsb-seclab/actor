#include <stdio.h>

int a () {
	int a = 3;
	int b =4;
	int *c = &b;
	int **d = &c;
	c = *d;
	b = *c;
	return a+b;
}

int b() {
	return 2 + a();
}

struct my_struct {
	int ind;
	int arr[10];
};

int c() {
	int a[10] = {1,2,3,4,5,6,7,8,9,10};
	struct my_struct m = {1, {1,2,3,4,5,6,7,8,9,10}};
	int res = 0;
	int i = 0;
	m.ind = 2;
	if (m.ind < 10) {
		i = m.ind;
	} else {
		i = 0;
	}
	res += m.arr[i];
	/*
	b +=1;
	res += a[b];
	b+=6;
	res += a[b];
	*/
	return res;
}

int main() {
	printf("%d\n", a());
	printf("%d\n", b());
	printf("%d\n", c());
	printf("hello world\n");
	return 0;
}
