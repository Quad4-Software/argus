(function () {
  var reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches

  var specs = [
    { follow: true, x: 50.0, y: 33.3, w: 29.6, h: 26.6 },
    { x: 23.0, y: 38.6, w: 17.4, h: 19.6 },
    { x: 77.2, y: 38.9, w: 17.4, h: 19.6 },
    { x: 25.8, y: 61.6, w: 15.6, h: 17.8 },
    { x: 74.0, y: 61.7, w: 15.6, h: 17.8 }
  ]

  function mount() {
    var root = document.createElement("div")
    root.className = "argus-mascot"
    root.setAttribute("aria-hidden", "true")

    var eyes = specs.map(function (spec) {
      var eye = document.createElement("div")
      eye.className = "argus-eye" + (spec.follow ? " argus-eye-main" : "")
      eye.style.left = spec.x + "%"
      eye.style.top = spec.y + "%"
      eye.style.width = spec.w + "%"
      eye.style.height = spec.h + "%"

      var mover = document.createElement("div")
      mover.className = "argus-mover"
      var pupilHost = mover
      if (spec.follow) {
        var iris = document.createElement("div")
        iris.className = "argus-iris"
        mover.appendChild(iris)
        pupilHost = iris
      }
      var pupil = document.createElement("div")
      pupil.className = "argus-pupil"
      var glint = document.createElement("div")
      glint.className = "argus-glint"
      pupil.appendChild(glint)
      pupilHost.appendChild(pupil)
      var sclera = document.createElement("div")
      sclera.className = "argus-sclera"
      var lidTop = document.createElement("div")
      lidTop.className = "argus-lid argus-lid-top"
      var lidBottom = document.createElement("div")
      lidBottom.className = "argus-lid argus-lid-bottom"
      eye.appendChild(sclera)
      eye.appendChild(mover)
      eye.appendChild(lidTop)
      eye.appendChild(lidBottom)
      root.appendChild(eye)

      return {
        el: eye,
        mover: mover,
        lidTop: lidTop,
        lidBottom: lidBottom,
        follow: !!spec.follow,
        tx: 0,
        ty: 0,
        x: 0,
        y: 0,
        next: 1400 + Math.random() * 2200,
        lag: spec.follow ? 0 : 16 + Math.random() * 36
      }
    })

    document.body.appendChild(root)
    var main = eyes[0]

    document.addEventListener("mousemove", function (ev) {
      var rect = main.el.getBoundingClientRect()
      var cx = rect.left + rect.width / 2
      var cy = rect.top + rect.height / 2
      var dx = ev.clientX - cx
      var dy = ev.clientY - cy
      var dist = Math.hypot(dx, dy) || 1
      var mag = Math.min(1, dist / 220)
      main.tx = (dx / dist) * mag
      main.ty = (dy / dist) * mag
    })

    document.documentElement.addEventListener("mouseleave", function () {
      main.tx = 0
      main.ty = 0
    })

    function place(eye) {
      var travel = (eye.follow ? 0.11 : 0.18) * eye.el.clientWidth
      eye.mover.style.transform =
        "translate(" + (eye.x * travel).toFixed(2) + "px," + (eye.y * travel).toFixed(2) + "px)"
    }

    var CLOSE_MS = 190
    var HOLD_MS = 90
    var OPEN_MS = 340
    var DOUBLE_GAP = 180
    var blink = { active: false, t0: 0, until: 0, double: false, next: 5200 }

    function easeIn(p) {
      return p * p * p
    }

    function easeOut(p) {
      return 1 - Math.pow(1 - p, 3)
    }

    function oneBlink(t, close, hold, open) {
      if (t < 0) return null
      if (t < close) return 1 - easeIn(t / close)
      t -= close
      if (t < hold) return 0
      t -= hold
      if (t < open) return easeOut(t / open)
      return null
    }

    function openAmount(elapsed) {
      var first = oneBlink(elapsed, CLOSE_MS, HOLD_MS, OPEN_MS)
      if (first !== null) return first
      var t = elapsed - (CLOSE_MS + HOLD_MS + OPEN_MS)
      if (!blink.double) return 1
      if (t < DOUBLE_GAP) return 1
      var second = oneBlink(t - DOUBLE_GAP, CLOSE_MS * 0.82, HOLD_MS * 0.55, OPEN_MS * 0.82)
      return second === null ? 1 : second
    }

    function placeLids(eye, shut) {
      eye.lidTop.style.transform = "translateY(" + (-104 + shut * 40).toFixed(2) + "%)"
      eye.lidBottom.style.transform = "translateY(" + (104 - shut * 40).toFixed(2) + "%)"
    }

    function parkLids(eye) {
      placeLids(eye, 0)
    }

    function setLids(eye, open) {
      placeLids(eye, 1 - open)
    }

    eyes.forEach(parkLids)

    function frame(now) {
      eyes.forEach(function (eye) {
        if (!eye.follow && !reduce && now > eye.next) {
          var angle = Math.random() * Math.PI * 2
          var mag = 0.2 + Math.random() * 0.8
          eye.tx = Math.cos(angle) * mag
          eye.ty = Math.sin(angle) * mag
          eye.next = now + 1600 + Math.random() * 2400
        }
        var ease = eye.follow ? 0.22 : 0.07
        eye.x += (eye.tx - eye.x) * ease
        eye.y += (eye.ty - eye.y) * ease
        place(eye)
      })

      if (!reduce) {
        if (!blink.active && now > blink.next) {
          blink.active = true
          blink.t0 = now
          blink.double = Math.random() < 0.22
          var span = CLOSE_MS + HOLD_MS + OPEN_MS
          if (blink.double) span += DOUBLE_GAP + (CLOSE_MS + HOLD_MS + OPEN_MS) * 0.82
          blink.until = now + span + 50
        }
        if (blink.active) {
          eyes.forEach(function (eye) {
            setLids(eye, openAmount(now - blink.t0 - eye.lag))
          })
          if (now > blink.until) {
            blink.active = false
            blink.next = now + 7000 + Math.random() * 5000
            eyes.forEach(parkLids)
          }
        }
      }

      requestAnimationFrame(frame)
    }

    requestAnimationFrame(frame)
  }

  if (document.body) mount()
  else document.addEventListener("DOMContentLoaded", mount)
})()
