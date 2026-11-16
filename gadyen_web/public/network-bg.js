/* Gadyen Safeguard background: a quiet, slowly moving network.
   Nodes drift, links appear between close nodes, a few data packets travel
   along the links, and some nodes carry a security symbol (shield, lock, key).
   Kept deliberately dim and slow so it never competes with the chat.
   - honours "prefers-reduced-motion" (draws one still frame)
   - pauses when the tab is hidden
   - capped at ~30 frames per second */
(function () {
    "use strict";

    var canvas = document.getElementById("net-bg");
    if (!canvas || !canvas.getContext) return;
    var ctx = canvas.getContext("2d");

    var LINK_DISTANCE = 170;
    var COLORS = {
        node: "120, 190, 255",
        link: "95, 170, 240",
        packet: "110, 225, 240",
        symbol: "150, 205, 255"
    };
    var reduceMotion = window.matchMedia &&
        window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    var width = 0, height = 0, dpr = 1;
    var nodes = [], packets = [];
    var lastFrame = 0, lastPacket = 0, running = false, frameId = 0;

    /* Symbols are drawn in a 24x24 box centred on the node. */
    var SYMBOLS = [
        function shield(c) {
            c.beginPath();
            c.moveTo(0, -11); c.lineTo(9, -7); c.lineTo(9, 0);
            c.bezierCurveTo(9, 6, 5, 10, 0, 12);
            c.bezierCurveTo(-5, 10, -9, 6, -9, 0);
            c.lineTo(-9, -7); c.closePath(); c.stroke();
            c.beginPath();
            c.moveTo(-4, 0); c.lineTo(-1, 3.5); c.lineTo(4.5, -3); c.stroke();
        },
        function lock(c) {
            c.beginPath();
            c.rect(-7, -1, 14, 11); c.stroke();
            c.beginPath();
            c.moveTo(-4.5, -1); c.lineTo(-4.5, -5);
            c.arc(0, -5, 4.5, Math.PI, 0, false);
            c.lineTo(4.5, -1); c.stroke();
            c.beginPath();
            c.arc(0, 4, 1.4, 0, Math.PI * 2); c.fill();
        },
        function key(c) {
            c.beginPath();
            c.arc(-6, 0, 4, 0, Math.PI * 2); c.stroke();
            c.beginPath();
            c.moveTo(-2, 0); c.lineTo(10, 0);
            c.moveTo(6, 0); c.lineTo(6, 4);
            c.moveTo(10, 0); c.lineTo(10, 3.5); c.stroke();
        }
    ];

    function rand(min, max) { return min + Math.random() * (max - min); }

    function build() {
        dpr = Math.min(window.devicePixelRatio || 1, 2);
        width = window.innerWidth;
        height = window.innerHeight;
        canvas.width = Math.round(width * dpr);
        canvas.height = Math.round(height * dpr);
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

        var count = Math.max(18, Math.min(64, Math.round(width * height / 19000)));
        var symbolCount = Math.max(3, Math.min(7, Math.round(count / 9)));
        nodes = [];
        for (var i = 0; i < count; i++) {
            nodes.push({
                x: rand(0, width), y: rand(0, height),
                vx: rand(-9, 9), vy: rand(-9, 9),      // pixels per second
                r: rand(1.2, 2.4),
                symbol: i < symbolCount ? SYMBOLS[i % SYMBOLS.length] : null,
                phase: rand(0, Math.PI * 2)
            });
        }
        packets = [];
    }

    function step(dt) {
        for (var i = 0; i < nodes.length; i++) {
            var n = nodes[i];
            n.x += n.vx * dt; n.y += n.vy * dt;
            if (n.x < -20) n.x = width + 20; else if (n.x > width + 20) n.x = -20;
            if (n.y < -20) n.y = height + 20; else if (n.y > height + 20) n.y = -20;
        }
        for (var p = packets.length - 1; p >= 0; p--) {
            packets[p].t += dt / packets[p].duration;
            if (packets[p].t >= 1) packets.splice(p, 1);
        }
    }

    function spawnPacket() {
        if (packets.length >= 5 || nodes.length < 2) return;
        for (var tries = 0; tries < 12; tries++) {
            var a = nodes[Math.floor(Math.random() * nodes.length)];
            var b = nodes[Math.floor(Math.random() * nodes.length)];
            if (a === b) continue;
            var d = Math.hypot(a.x - b.x, a.y - b.y);
            if (d > 60 && d < LINK_DISTANCE) {
                packets.push({ a: a, b: b, t: 0, duration: rand(2.2, 3.6) });
                return;
            }
        }
    }

    function draw(time) {
        ctx.clearRect(0, 0, width, height);
        ctx.lineWidth = 1;

        // links
        for (var i = 0; i < nodes.length; i++) {
            for (var j = i + 1; j < nodes.length; j++) {
                var a = nodes[i], b = nodes[j];
                var dx = a.x - b.x, dy = a.y - b.y;
                if (Math.abs(dx) > LINK_DISTANCE || Math.abs(dy) > LINK_DISTANCE) continue;
                var d = Math.sqrt(dx * dx + dy * dy);
                if (d > LINK_DISTANCE) continue;
                ctx.strokeStyle = "rgba(" + COLORS.link + "," +
                    (0.30 * (1 - d / LINK_DISTANCE)).toFixed(3) + ")";
                ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
            }
        }

        // nodes and symbols
        for (var k = 0; k < nodes.length; k++) {
            var n = nodes[k];
            if (n.symbol) {
                // slow "watching" pulse: a ring that breathes around the symbol
                var breath = 0.5 + 0.5 * Math.sin(time / 2600 + n.phase);
                ctx.strokeStyle = "rgba(" + COLORS.symbol + "," + (0.05 + 0.07 * breath).toFixed(3) + ")";
                ctx.beginPath();
                ctx.arc(n.x, n.y, 22 + 5 * breath, 0, Math.PI * 2); ctx.stroke();

                ctx.save();
                ctx.translate(n.x, n.y);
                ctx.lineWidth = 1.4;
                ctx.lineJoin = "round"; ctx.lineCap = "round";
                ctx.strokeStyle = "rgba(" + COLORS.symbol + ",0.42)";
                ctx.fillStyle = "rgba(" + COLORS.symbol + ",0.42)";
                n.symbol(ctx);
                ctx.restore();
                ctx.lineWidth = 1;
            } else {
                ctx.fillStyle = "rgba(" + COLORS.node + ",0.5)";
                ctx.beginPath(); ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2); ctx.fill();
            }
        }

        // packets travelling along links
        for (var p = 0; p < packets.length; p++) {
            var pk = packets[p];
            var x = pk.a.x + (pk.b.x - pk.a.x) * pk.t;
            var y = pk.a.y + (pk.b.y - pk.a.y) * pk.t;
            var fade = Math.sin(Math.PI * pk.t);
            ctx.fillStyle = "rgba(" + COLORS.packet + "," + (0.16 * fade).toFixed(3) + ")";
            ctx.beginPath(); ctx.arc(x, y, 6, 0, Math.PI * 2); ctx.fill();
            ctx.fillStyle = "rgba(" + COLORS.packet + "," + (0.85 * fade).toFixed(3) + ")";
            ctx.beginPath(); ctx.arc(x, y, 1.8, 0, Math.PI * 2); ctx.fill();
        }
    }

    function frame(time) {
        if (!running) return;
        frameId = requestAnimationFrame(frame);
        var elapsed = time - lastFrame;
        if (elapsed < 33) return;                       // ~30 fps
        lastFrame = time;
        step(Math.min(elapsed, 100) / 1000);
        if (time - lastPacket > 1400) { spawnPacket(); lastPacket = time; }
        draw(time);
    }

    function start() {
        if (running || reduceMotion) return;
        running = true;
        lastFrame = performance.now();
        frameId = requestAnimationFrame(frame);
    }

    function stop() {
        running = false;
        cancelAnimationFrame(frameId);
    }

    var resizeTimer = 0;
    window.addEventListener("resize", function () {
        clearTimeout(resizeTimer);
        resizeTimer = setTimeout(function () { build(); draw(performance.now()); }, 150);
    });
    document.addEventListener("visibilitychange", function () {
        if (document.hidden) stop(); else start();
    });

    build();
    draw(0);
    start();
})();
