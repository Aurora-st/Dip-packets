import React, { useRef, useEffect } from "react";
import { motion } from "framer-motion";

export default function RobotMascot({ state }) {
  // state can be "idle", "loading", or "complete"
  const videoRef = useRef(null);

  // Log state changes to console for verification
  console.log("[RobotMascot] State changed to:", state);

  useEffect(() => {
    if (!videoRef.current) return;

    if (state === "loading") {
      // 1. Reset playback rate to 1.0x speed to prevent video buffering/stuttering
      videoRef.current.playbackRate = 1.0;
      
      const playPromise = videoRef.current.play();
      if (playPromise !== undefined) {
        playPromise.catch((error) => {
          console.debug("Video play prevented or interrupted:", error);
        });
      }
    } else {
      videoRef.current.pause();
    }
  }, [state]);

  const isLoading = state === "loading";
  
  // Show text conditionally:
  // - If state === "loading": show "🔄 Pulling live data..." in cyan
  // - If state === "complete" or "idle": show "⚡ Sync Complete!" in cyan
  const statusText = isLoading ? "🔄 Pulling live data..." : "⚡ Sync Complete!";

  return (
    <div style={{
      display: "flex",
      flexDirection: "column",
      alignItems: "center",
      justifyContent: "center",
      padding: "20px",
      width: "100%",
      maxWidth: "280px",
      minHeight: "280px", // Fixed minHeight to prevent squishing and clipping
      textAlign: "center",
      boxSizing: "border-box"
    }}
    className="glass-card"
    >
      {/* Video Container with custom shadow, fast shake, and fast glow when loading */}
      <div 
        className={isLoading ? "animate-urgent-glow animate-urgent-shake" : ""}
        style={{
          width: "180px",
          height: "180px",
          position: "relative",
          borderRadius: "16px",
          overflow: "hidden",
          border: `2px solid ${isLoading ? "rgba(0, 217, 255, 0.5)" : "rgba(255,255,255,0.05)"}`,
          boxShadow: isLoading 
            ? "0 0 25px 6px rgba(0, 217, 255, 0.45)" 
            : "0 4px 12px rgba(0,0,0,0.2)",
          transition: isLoading ? "none" : "all 0.3s ease",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          background: "rgba(15, 23, 42, 0.6)"
        }}
      >
        <video
          ref={videoRef}
          src="/videos/robot.k.mp4"
          loop
          muted
          playsInline
          style={{
            width: "100%",
            height: "100%",
            objectFit: "cover"
          }}
        />
      </div>

      {/* Visually prominent cyan bold status text directly below the video */}
      <div 
        className={isLoading ? "animate-urgent-text" : ""}
        style={{
          marginTop: "12px", // 12px spacing between video and text
          fontSize: "16px",  // 16px size
          fontWeight: 700,   // Bold
          color: "#00d9ff", // Cyan
          letterSpacing: "-0.01em",
          display: "block",
          textShadow: "0 0 8px rgba(0, 217, 255, 0.35)",
          transition: "all 0.2s ease"
        }}
      >
        {statusText}
      </div>
      
      {/* Sync Progress Bar */}
      <div style={{
        width: "140px",
        height: "3px",
        backgroundColor: "rgba(255,255,255,0.05)",
        borderRadius: "2px",
        marginTop: "12px",
        position: "relative",
        overflow: "hidden"
      }}>
        <motion.div
          style={{
            height: "100%",
            width: "100%",
            backgroundColor: "#00d9ff", // Cyan progress bar
            position: "absolute",
            left: 0,
            top: 0
          }}
          initial={{ x: "-100%" }}
          animate={
            isLoading
              ? { x: ["-100%", "100%"] }
              : { x: "0%" }
          }
          transition={
            isLoading
              ? { repeat: Infinity, duration: 1.0, ease: "easeInOut" }
              : { duration: 0.2 }
          }
        />
      </div>
    </div>
  );
}
