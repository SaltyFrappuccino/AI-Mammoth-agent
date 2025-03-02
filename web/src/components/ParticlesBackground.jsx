import React, { useCallback } from 'react';
import Particles from 'react-particles';
import { loadSlim } from 'tsparticles-slim';

const ParticlesBackground = () => {
  // Цвета из градиента Сбера для частиц
  const colors = [
    '#21A038', // Зеленый (primary)
    '#6ECF81', // Весенний (spring)
    '#FDD835', // Солнечный (sun)
    '#85D9F0', // Арктический (arctic)
    '#0087CD'  // Синий (secondary)
  ];

  const particlesInit = useCallback(async (engine) => {
    await loadSlim(engine);
  }, []);

  return (
    <Particles
      id="tsparticles"
      init={particlesInit}
      options={{
        fullScreen: {
          enable: true,
          zIndex: -1
        },
        background: {
          color: {
            value: 'transparent',
          },
        },
        fpsLimit: 60,
        particles: {
          color: {
            value: colors,
          },
          links: {
            color: '#e0e0e0',
            distance: 150,
            enable: true,
            opacity: 0.3,
            width: 1,
          },
          collisions: {
            enable: false,
          },
          move: {
            direction: 'none',
            enable: true,
            outModes: {
              default: 'bounce',
            },
            random: true,
            speed: 1,
            straight: false,
          },
          number: {
            density: {
              enable: true,
              area: 800,
            },
            value: 70,
          },
          opacity: {
            value: 0.5,
          },
          shape: {
            type: 'circle',
          },
          size: {
            value: { min: 1, max: 5 },
          },
        },
        detectRetina: true,
        interactivity: {
          events: {
            onHover: {
              enable: true,
              mode: 'grab',
            },
            onClick: {
              enable: true,
              mode: 'push',
            },
          },
          modes: {
            grab: {
              distance: 140,
              links: {
                opacity: 0.8
              }
            },
            push: {
              quantity: 4,
            },
          },
        },
      }}
    />
  );
};

export default ParticlesBackground; 